package instance

import (
	"fmt"
	"net"
	"sync"
)

// Service represents a service that can be started and stopped
type Service interface {
	// Start initiates the service with the given connection
	Start(conn net.Conn) error
	// Stop gracefully shuts down the service
	Stop() error
	// Type returns the service type identifier
	Type() string
}

// ServiceManager manages multiple services and dispatches incoming connections
type ServiceManager struct {
	services map[string]Service
	mutex    sync.RWMutex
}

// NewServiceManager creates a new service manager
func NewServiceManager() *ServiceManager {
	return &ServiceManager{
		services: make(map[string]Service),
	}
}

// RegisterService registers a service with the manager
func (sm *ServiceManager) RegisterService(service Service) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	serviceType := service.Type()
	if _, exists := sm.services[serviceType]; exists {
		return fmt.Errorf("service type %s already registered", serviceType)
	}

	sm.services[serviceType] = service
	return nil
}

// GetService retrieves a service by type
func (sm *ServiceManager) GetService(serviceType string) (Service, error) {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	service, exists := sm.services[serviceType]
	if !exists {
		return nil, fmt.Errorf("service type %s not found", serviceType)
	}

	return service, nil
}

// HandleConnection dispatches a connection to the appropriate service
func (sm *ServiceManager) HandleConnection(serviceType string, conn net.Conn) error {
	service, err := sm.GetService(serviceType)
	if err != nil {
		return err
	}

	return service.Start(conn)
}

// StopAll stops all registered services
func (sm *ServiceManager) StopAll() error {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	var errs []error
	for _, service := range sm.services {
		if err := service.Stop(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to stop %d service(s)", len(errs))
	}

	return nil
}
