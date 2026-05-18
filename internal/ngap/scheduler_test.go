package ngap

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock connection for testing
type mockConn struct {
	net.Conn
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHashUEID_Consistency(t *testing.T) {
	// Test that the same UE ID always hashes to the same worker
	numWorkers := 8
	scheduler := NewUEScheduler(numWorkers, 100, func(conn net.Conn, msg []byte) {})
	defer scheduler.Shutdown()

	testUEIDs := []uint64{1, 100, 1000, 12345, 67890, 999999}

	for _, ueID := range testUEIDs {
		// Hash the same UE ID multiple times
		firstHash := scheduler.hashUEID(ueID)

		for i := 0; i < 100; i++ {
			hash := scheduler.hashUEID(ueID)
			assert.Equal(t, firstHash, hash,
				"UE ID %d should always hash to the same worker (expected %d, got %d)",
				ueID, firstHash, hash)
		}
	}
}

func TestHashUEID_Distribution(t *testing.T) {
	// Test that UE IDs are distributed evenly across workers
	numWorkers := 8
	scheduler := NewUEScheduler(numWorkers, 100, func(conn net.Conn, msg []byte) {})
	defer scheduler.Shutdown()

	// Generate a large number of UE IDs
	numUEs := 10000
	distribution := make(map[int]int)

	for i := 0; i < numUEs; i++ {
		ueID := uint64(i + 1)
		workerIndex := scheduler.hashUEID(ueID)
		distribution[workerIndex]++
	}

	// Verify all workers got some UEs
	assert.Equal(t, numWorkers, len(distribution),
		"All workers should receive some UEs")

	// Calculate expected count per worker (with some tolerance)
	expectedPerWorker := numUEs / numWorkers
	tolerance := expectedPerWorker / 4 // 25% tolerance

	for workerID, count := range distribution {
		t.Logf("Worker %d received %d UEs (expected ~%d)",
			workerID, count, expectedPerWorker)

		assert.GreaterOrEqual(t, count, expectedPerWorker-tolerance,
			"Worker %d received too few UEs", workerID)
		assert.LessOrEqual(t, count, expectedPerWorker+tolerance,
			"Worker %d received too many UEs", workerID)
	}
}

func TestHashUEID_Range(t *testing.T) {
	// Test that hash function always returns valid worker index
	numWorkers := 8
	scheduler := NewUEScheduler(numWorkers, 100, func(conn net.Conn, msg []byte) {})
	defer scheduler.Shutdown()

	// Test with various UE IDs
	testCases := []uint64{
		0, 1, 100, 1000, 10000,
		^uint64(0) - 1, // Max uint64 - 1
		^uint64(0),     // Max uint64
	}

	for _, ueID := range testCases {
		workerIndex := scheduler.hashUEID(ueID)
		assert.GreaterOrEqual(t, workerIndex, 0,
			"Worker index should be >= 0 for UE ID %d", ueID)
		assert.Less(t, workerIndex, numWorkers,
			"Worker index should be < numWorkers for UE ID %d", ueID)
	}
}

func TestScheduler_ConcurrentTaskSubmission(t *testing.T) {
	// Test scheduler with concurrent task submissions
	numWorkers := 4
	numGoroutines := 50
	tasksPerGoroutine := 100

	var processedCount int32
	var mu sync.Mutex
	processedByWorker := make(map[int]int)

	// WaitGroup to track task processing completion
	var processingWg sync.WaitGroup
	processingWg.Add(numGoroutines * tasksPerGoroutine)

	handler := func(conn net.Conn, msg []byte) {
		atomic.AddInt32(&processedCount, 1)
		processingWg.Done()
	}

	scheduler := NewUEScheduler(numWorkers, 1000, handler)
	defer scheduler.Shutdown()

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch multiple goroutines submitting tasks concurrently
	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()

			for i := 0; i < tasksPerGoroutine; i++ {
				ueID := uint64(goroutineID*tasksPerGoroutine + i)
				task := Task{
					UEID:    ueID,
					Conn:    &mockConn{},
					Message: []byte{0x00, 0x01, 0x02},
				}

				workerIndex := scheduler.hashUEID(ueID)
				mu.Lock()
				processedByWorker[workerIndex]++
				mu.Unlock()

				scheduler.DispatchTask(task)
			}
		}(g)
	}

	// Wait for all submissions to complete
	wg.Wait()

	// Wait for all tasks to be processed
	processingWg.Wait()

	expectedTotal := numGoroutines * tasksPerGoroutine
	actualProcessed := atomic.LoadInt32(&processedCount)

	t.Logf("Expected %d tasks, processed %d tasks", expectedTotal, actualProcessed)
	assert.Equal(t, int32(expectedTotal), actualProcessed,
		"All tasks should be processed")

	// Verify distribution
	t.Log("Tasks processed per worker:")
	for i := 0; i < numWorkers; i++ {
		count := processedByWorker[i]
		t.Logf("  Worker %d: %d tasks", i, count)
	}
}

func TestScheduler_PerUESequentiality(t *testing.T) {
	// Test that messages for the same UE are processed in order
	numWorkers := 4
	ueID := uint64(12345)
	numMessages := 100

	var processedOrder []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(numMessages)

	handler := func(conn net.Conn, msg []byte) {
		// Extract message sequence number from message
		seqNum := int(msg[0])
		mu.Lock()
		processedOrder = append(processedOrder, seqNum)
		mu.Unlock()
		wg.Done()
	}

	scheduler := NewUEScheduler(numWorkers, 1000, handler)
	defer scheduler.Shutdown()

	// Submit messages for the same UE in order
	for i := 0; i < numMessages; i++ {
		task := Task{
			UEID:    ueID,
			Conn:    &mockConn{},
			Message: []byte{byte(i)},
		}
		scheduler.DispatchTask(task)
	}

	// Wait for all messages to be processed
	wg.Wait()

	// Verify messages were processed in order
	require.Equal(t, numMessages, len(processedOrder),
		"All messages should be processed")

	for i := 0; i < numMessages; i++ {
		assert.Equal(t, i, processedOrder[i],
			"Message %d should be processed in order", i)
	}
}

func TestScheduler_MultipleUEsConcurrent(t *testing.T) {
	// Test multiple UEs being processed concurrently
	numWorkers := 8
	numUEs := 20
	messagesPerUE := 50

	processedByUE := make(map[uint64][]int)
	var mu sync.Mutex

	// WaitGroup to track processing completion
	var processingWg sync.WaitGroup
	processingWg.Add(numUEs * messagesPerUE)

	handler := func(conn net.Conn, msg []byte) {
		ueID := uint64(msg[0])
		seqNum := int(msg[1])

		mu.Lock()
		processedByUE[ueID] = append(processedByUE[ueID], seqNum)
		mu.Unlock()

		processingWg.Done()
	}

	scheduler := NewUEScheduler(numWorkers, 1000, handler)
	defer scheduler.Shutdown()

	var wg sync.WaitGroup
	wg.Add(numUEs)

	// Each UE submits messages in its own goroutine
	for ueIdx := 0; ueIdx < numUEs; ueIdx++ {
		go func(ueID uint64) {
			defer wg.Done()

			for msgIdx := 0; msgIdx < messagesPerUE; msgIdx++ {
				task := Task{
					UEID:    ueID,
					Conn:    &mockConn{},
					Message: []byte{byte(ueID), byte(msgIdx)},
				}
				scheduler.DispatchTask(task)
			}
		}(uint64(ueIdx))
	}

	// Wait for all submissions
	wg.Wait()

	// Wait for all processing to complete
	processingWg.Wait()

	// Verify each UE's messages were processed in order
	for ueID := uint64(0); ueID < uint64(numUEs); ueID++ {
		messages := processedByUE[ueID]
		require.Equal(t, messagesPerUE, len(messages),
			"UE %d should have all messages processed", ueID)

		for i := 0; i < messagesPerUE; i++ {
			assert.Equal(t, i, messages[i],
				"UE %d message %d should be in order", ueID, i)
		}
	}
}

func TestScheduler_GracefulShutdown(t *testing.T) {
	// Test graceful shutdown of scheduler - ensures all queued tasks are drained
	numWorkers := 4
	numTasks := 50

	var processedCount int32
	var processingWg sync.WaitGroup
	processingWg.Add(numTasks)

	handler := func(conn net.Conn, msg []byte) {
		atomic.AddInt32(&processedCount, 1)
		time.Sleep(10 * time.Millisecond)
		processingWg.Done()
	}

	scheduler := NewUEScheduler(numWorkers, 100, handler)

	// Submit all tasks
	for i := 0; i < numTasks; i++ {
		task := Task{
			UEID:    uint64(i),
			Conn:    &mockConn{},
			Message: []byte{0x00},
		}
		scheduler.DispatchTask(task)
	}

	// Shutdown waits for all workers to finish processing their queues
	scheduler.Shutdown()

	// Wait for all tasks to be processed
	processingWg.Wait()

	// Verify all tasks were processed (queue draining guarantee)
	processed := atomic.LoadInt32(&processedCount)
	t.Logf("Processed %d tasks before shutdown", processed)
	assert.Equal(t, int32(numTasks), processed,
		"All queued tasks should be processed during graceful shutdown")
}

func TestScheduler_WorkerCount(t *testing.T) {
	testCases := []struct {
		name          string
		numWorkers    int
		expectedCount int
	}{
		{"Single worker", 1, 1},
		{"Four workers", 4, 4},
		{"Eight workers", 8, 8},
		{"Auto-detect (0)", 0, -1}, // -1 means check > 0
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scheduler := NewUEScheduler(tc.numWorkers, 100,
				func(conn net.Conn, msg []byte) {})
			defer scheduler.Shutdown()

			actualCount := len(scheduler.workers)
			if tc.expectedCount == -1 {
				assert.Greater(t, actualCount, 0,
					"Auto-detected worker count should be > 0")
			} else {
				assert.Equal(t, tc.expectedCount, actualCount,
					"Worker count should match expected")
			}
		})
	}
}

func TestScheduler_NonUEMessage(t *testing.T) {
	// Test handling of non-UE messages (UE ID = 0)
	numWorkers := 4
	numMessages := 20

	var processedCount int32
	var wg sync.WaitGroup
	wg.Add(numMessages)

	handler := func(conn net.Conn, msg []byte) {
		atomic.AddInt32(&processedCount, 1)
		wg.Done()
	}

	scheduler := NewUEScheduler(numWorkers, 100, handler)
	defer scheduler.Shutdown()

	// Submit non-UE messages (UE ID = 0)
	// All should go to the same worker (determined by hash)
	expectedWorkerIndex := scheduler.hashUEID(0)

	for i := 0; i < numMessages; i++ {
		task := Task{
			UEID:    0, // Non-UE message
			Conn:    &mockConn{},
			Message: []byte{0x00},
		}

		// Verify they all go to the same worker
		workerIndex := scheduler.hashUEID(0)
		assert.Equal(t, expectedWorkerIndex, workerIndex,
			"All non-UE messages should route to the same worker")

		scheduler.DispatchTask(task)
	}

	// Wait for all messages to be processed
	wg.Wait()

	assert.Equal(t, int32(numMessages), atomic.LoadInt32(&processedCount),
		"All non-UE messages should be processed")
	t.Logf("Non-UE messages routed to worker %d", expectedWorkerIndex)
}
