package ngap

import (
	"fmt"
	"hash/fnv"
	"net"
	"runtime"
	"sync"

	"github.com/free5gc/amf/internal/logger"
)

// Task represents a work item to be processed by a worker.
// It contains the UE identifier and the raw NGAP message.
type Task struct {
	UEID    uint64   // AMF-UE-NGAP-ID or RAN-UE-NGAP-ID
	Conn    net.Conn // The network connection for this message
	Message []byte   // The raw NGAP message bytes
}

// Worker represents a goroutine that processes tasks from its dedicated queue.
type Worker struct {
	ID       int
	taskChan chan Task
	handler  func(conn net.Conn, msg []byte)
	wg       *sync.WaitGroup
	stopChan chan struct{}
}

// NewWorker creates and starts a new worker goroutine.
func NewWorker(id int, bufferSize int, handler func(conn net.Conn, msg []byte), wg *sync.WaitGroup) *Worker {
	w := &Worker{
		ID:       id,
		taskChan: make(chan Task, bufferSize),
		handler:  handler,
		wg:       wg,
		stopChan: make(chan struct{}),
	}
	wg.Add(1)
	go w.run()
	return w
}

// run is the main event loop for the worker.
func (w *Worker) run() {
	defer w.wg.Done()
	logger.NgapLog.Infof("Worker %d started", w.ID)

	for {
		select {
		case task, ok := <-w.taskChan:
			if !ok {
				logger.NgapLog.Infof("Worker %d: task channel closed, shutting down", w.ID)
				return
			}
			logger.NgapLog.Debugf("Worker %d processing task for UE ID %d (ensuring per-UE sequentiality)",
				w.ID, task.UEID)
			w.handler(task.Conn, task.Message)
		case <-w.stopChan:
			logger.NgapLog.Infof("Worker %d: stop signal received, shutting down", w.ID)
			return
		}
	}
}

// Stop gracefully stops the worker.
func (w *Worker) Stop() {
	close(w.stopChan)
}

// Submit submits a task to this worker's queue.
func (w *Worker) Submit(task Task) {
	w.taskChan <- task
}

// UEScheduler distributes NGAP tasks to workers based on UE ID.
type UEScheduler struct {
	workers     []*Worker
	numWorkers  int
	workerMutex sync.RWMutex
}

// NewUEScheduler creates a new UE scheduler with the specified number of workers.
func NewUEScheduler(numWorkers int, taskBufferSize int, handler func(conn net.Conn, msg []byte)) *UEScheduler {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
		logger.NgapLog.Infof("Invalid worker count, using default: %d (NumCPU)", numWorkers)
	}

	logger.NgapLog.Infof("Initializing UE Scheduler with %d workers", numWorkers)

	scheduler := &UEScheduler{
		workers:    make([]*Worker, numWorkers),
		numWorkers: numWorkers,
	}

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		scheduler.workers[i] = NewWorker(i, taskBufferSize, handler, &wg)
	}

	return scheduler
}

// DispatchTask dispatches a task to the appropriate worker based on UE ID hashing.
func (s *UEScheduler) DispatchTask(task Task) {
	s.workerMutex.RLock()
	defer s.workerMutex.RUnlock()

	// Hash the UE ID to determine which worker should handle it
	workerIndex := s.hashUEID(task.UEID)
	logger.NgapLog.Debugf("Dispatching UE ID %d to Worker %d (hash-based routing)",
		task.UEID, workerIndex)
	s.workers[workerIndex].Submit(task)
}

// hashUEID computes a hash of the UE ID and maps it to a worker index.
// This ensures all messages for the same UE go to the same worker.
func (s *UEScheduler) hashUEID(ueID uint64) int {
	h := fnv.New64a()
	// Convert uint64 to bytes for hashing
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(ueID >> (i * 8))
	}
	h.Write(b)
	return int(h.Sum64() % uint64(s.numWorkers))
}

// Shutdown gracefully shuts down all workers.
func (s *UEScheduler) Shutdown() {
	s.workerMutex.Lock()
	defer s.workerMutex.Unlock()

	logger.NgapLog.Info("Shutting down UE Scheduler and all workers...")

	var wg sync.WaitGroup
	for i, worker := range s.workers {
		wg.Add(1)
		go func(idx int, w *Worker) {
			defer wg.Done()
			logger.NgapLog.Infof("Closing task channel for Worker %d", idx)
			close(w.taskChan)
		}(i, worker)
	}
	wg.Wait()

	logger.NgapLog.Info("All workers shut down successfully")
}

// Global scheduler instance
var (
	globalScheduler     *UEScheduler
	globalSchedulerOnce sync.Once
	schedulerMutex      sync.RWMutex
)

// InitScheduler initializes the global UE scheduler.
// Should be called once during AMF startup.
func InitScheduler(numWorkers int, taskBufferSize int, handler func(conn net.Conn, msg []byte)) error {
	var initErr error
	globalSchedulerOnce.Do(func() {
		if numWorkers <= 0 {
			numWorkers = runtime.NumCPU()
		}
		if taskBufferSize <= 0 {
			taskBufferSize = 1000 // Default buffer size
		}

		schedulerMutex.Lock()
		defer schedulerMutex.Unlock()

		globalScheduler = NewUEScheduler(numWorkers, taskBufferSize, handler)
		logger.NgapLog.Infof("Global UE Scheduler initialized with %d workers, buffer size %d",
			numWorkers, taskBufferSize)
	})
	return initErr
}

// GetScheduler returns the global scheduler instance.
func GetScheduler() (*UEScheduler, error) {
	schedulerMutex.RLock()
	defer schedulerMutex.RUnlock()

	if globalScheduler == nil {
		return nil, fmt.Errorf("scheduler not initialized")
	}
	return globalScheduler, nil
}

// ShutdownScheduler gracefully shuts down the global scheduler.
func ShutdownScheduler() {
	schedulerMutex.Lock()
	defer schedulerMutex.Unlock()

	if globalScheduler != nil {
		globalScheduler.Shutdown()
		globalScheduler = nil
	}
}
