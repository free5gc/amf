package context

import (
	"testing"

	"github.com/sirupsen/logrus"
)

func TestSwitchToRanRejectsOccupiedID(t *testing.T) {
	log := logrus.New().WithField("test", t.Name())

	sourceRan := &AmfRan{Name: "source"}
	targetRan := &AmfRan{Name: "target"}

	existingUE := &RanUe{
		Ran:                 targetRan,
		RanUeNgapId:         42,
		RanUeNgapIdAssigned: true,
		Log:                 log,
	}
	movingUE := &RanUe{
		Ran:                 sourceRan,
		RanUeNgapId:         99,
		RanUeNgapIdAssigned: true,
		Log:                 log,
	}

	targetRan.RanUeList.Store(int64(42), existingUE)
	sourceRan.RanUeList.Store(int64(99), movingUE)

	err := movingUE.SwitchToRan(targetRan, 42)
	if err == nil {
		t.Fatal("expected an error for an ID occupied by another UE")
	}

	// The existing UE must keep its target mapping.
	if actual, ok := targetRan.RanUeList.Load(int64(42)); !ok || actual != existingUE {
		t.Fatal("target mapping was removed or overwritten")
	}

	// The moving UE must keep its source mapping.
	if actual, ok := sourceRan.RanUeList.Load(int64(99)); !ok || actual != movingUE {
		t.Fatal("source mapping was removed or changed")
	}

	// A rejected switch must not change either UE's RAN or ID.
	if movingUE.Ran != sourceRan ||
		movingUE.RanUeNgapId != 99 ||
		!movingUE.RanUeNgapIdAssigned {
		t.Fatal("moving UE fields changed after rejected switch")
	}
	if existingUE.Ran != targetRan ||
		existingUE.RanUeNgapId != 42 ||
		!existingUE.RanUeNgapIdAssigned {
		t.Fatal("existing UE fields changed after rejected switch")
	}
}

func TestSwitchToRanAvailableID(t *testing.T) {
	log := logrus.New().WithField("test", t.Name())

	sourceRan := &AmfRan{Name: "source"}
	targetRan := &AmfRan{Name: "target"}

	ue := &RanUe{
		Ran:                 sourceRan,
		RanUeNgapId:         99,
		RanUeNgapIdAssigned: true,
		Log:                 log,
	}
	sourceRan.RanUeList.Store(int64(99), ue)

	if err := ue.SwitchToRan(targetRan, 42); err != nil {
		t.Fatalf("switch to available ID failed: %v", err)
	}

	if _, ok := sourceRan.RanUeList.Load(int64(99)); ok {
		t.Fatal("old source mapping remains after successful switch")
	}
	if actual, ok := targetRan.RanUeList.Load(int64(42)); !ok || actual != ue {
		t.Fatal("target mapping does not point to the moving UE")
	}
	if ue.Ran != targetRan || ue.RanUeNgapId != 42 || !ue.RanUeNgapIdAssigned {
		t.Fatal("UE fields were not updated after successful switch")
	}
}

func TestSwitchToRanSameRanSameID(t *testing.T) {
	log := logrus.New().WithField("test", t.Name())

	ran := &AmfRan{Name: "same"}
	ue := &RanUe{
		Ran:                 ran,
		RanUeNgapId:         42,
		RanUeNgapIdAssigned: true,
		Log:                 log,
	}
	ran.RanUeList.Store(int64(42), ue)

	if err := ue.SwitchToRan(ran, 42); err != nil {
		t.Fatalf("switch to own mapping failed: %v", err)
	}

	if actual, ok := ran.RanUeList.Load(int64(42)); !ok || actual != ue {
		t.Fatal("switch to same RAN and ID deleted its own mapping")
	}
	if ue.Ran != ran || ue.RanUeNgapId != 42 || !ue.RanUeNgapIdAssigned {
		t.Fatal("UE fields changed unexpectedly")
	}
}
