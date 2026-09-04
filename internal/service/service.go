// Package service coordinates parsing, policy evaluation, durable state, and
// optional containment. It contains no platform-specific privileged code.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dwebserver/dweb-mail-abuse-guard/internal/config"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/event"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/incident"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/notify"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/policy"
	"github.com/dwebserver/dweb-mail-abuse-guard/internal/store"
)

type State interface {
	AppendEvent(event.Event) error
	CreateIncident(store.Incident) (store.Incident, bool, error)
	UpdateIncidentStatus(string, store.IncidentStatus, time.Time) error
}

type Containment interface {
	Contain(context.Context, string, string) error
}

type IDGenerator func(time.Time) (string, error)

type Service struct {
	mode       config.Mode
	policies   interface{ PolicyFor(string) config.Policy }
	engine     *policy.Engine
	state      State
	actions    Containment
	notifier   notify.Sender
	logger     *slog.Logger
	newID      IDGenerator
	notifyWait time.Duration
	mu         sync.Mutex
}

func New(cfg config.Config, engine *policy.Engine, state State, actions Containment, notifier notify.Sender, logger *slog.Logger) *Service {
	if notifier == nil {
		notifier = notify.Noop{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		mode:       cfg.Mode,
		policies:   cfg,
		engine:     engine,
		state:      state,
		actions:    actions,
		notifier:   notifier,
		logger:     logger,
		newID:      incident.NewID,
		notifyWait: cfg.Notification.Timeout,
	}
}

// Handle persists an event before evaluating it. Serializing the decision and
// incident creation keeps duplicate log readers from triggering two actions.
func (s *Service) Handle(ctx context.Context, item event.Event) (policy.Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.state.AppendEvent(item); err != nil {
		return policy.Decision{}, fmt.Errorf("persist event: %w", err)
	}
	decision := s.engine.Evaluate(item)
	if decision.Severity == policy.None {
		return decision, nil
	}

	id, err := s.newID(decision.Time)
	if err != nil {
		return decision, err
	}
	configured := s.policies.PolicyFor(decision.Mailbox)
	status := store.IncidentAudit
	if s.mode == config.Enforce && decision.Severity == policy.Contain {
		status = store.IncidentPending
	}
	candidate := store.Incident{
		ID: id, Mailbox: decision.Mailbox, Status: status, Decision: decision,
		CreatedAt: decision.Time, UpdatedAt: decision.Time,
		ExpiresAt: decision.Time.Add(configured.IncidentCooldown),
	}
	createdIncident, created, err := s.state.CreateIncident(candidate)
	if err != nil {
		return decision, fmt.Errorf("create incident: %w", err)
	}
	if !created {
		return decision, nil
	}

	if status == store.IncidentPending {
		if s.actions == nil {
			_ = s.state.UpdateIncidentStatus(id, store.IncidentFailed, time.Now().UTC())
			return decision, fmt.Errorf("containment helper is not configured")
		}
		if err := s.actions.Contain(ctx, decision.Mailbox, id); err != nil {
			_ = s.state.UpdateIncidentStatus(id, store.IncidentFailed, time.Now().UTC())
			s.logger.Error("mailbox containment failed", "incident", id, "mailbox", decision.Mailbox, "error", err)
			return decision, err
		}
		createdIncident.Status = store.IncidentContained
		createdIncident.UpdatedAt = time.Now().UTC()
		if err := s.state.UpdateIncidentStatus(id, store.IncidentContained, createdIncident.UpdatedAt); err != nil {
			return decision, fmt.Errorf("record containment: %w", err)
		}
	}

	s.logger.Warn("mail abuse incident", "incident", id, "mailbox", decision.Mailbox, "severity", decision.Severity, "mode", s.mode, "signals", decision.Signals)
	if err := s.sendNotification(ctx, createdIncident); err != nil {
		s.logger.Error("incident notification failed", "incident", id, "error", err)
	}
	return decision, nil
}

func (s *Service) sendNotification(ctx context.Context, created store.Incident) error {
	timeout := s.notifyWait
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	notifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return s.notifier.Send(notifyCtx, created)
}
