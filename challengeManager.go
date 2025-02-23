package main

import (
	"log"
	"sync"
	"time"
)

type ChallengeManager struct {
	solvedChallenges map[string]int64
	mu               sync.Mutex
	expireDuration   time.Duration
}

func NewChallengeManager(expireDuration string) *ChallengeManager {
	duration, err := time.ParseDuration(expireDuration)
	if err != nil {
		panic(err)
	}
	cm := &ChallengeManager{
		solvedChallenges: make(map[string]int64),
		expireDuration:   duration,
	}
	go cm.cleanupLoop()
	return cm
}

func (cm *ChallengeManager) AddChallenge(challenge string, expireAt int64) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.solvedChallenges[challenge] = expireAt
}

func (cm *ChallengeManager) Exists(challenge string) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	_, ok := cm.solvedChallenges[challenge]
	if ok {
		return true
	}
	return false
}

func (cm *ChallengeManager) cleanupLoop() {
	ticker := time.NewTicker(cm.expireDuration)
	defer ticker.Stop()

	for range ticker.C {
		cm.cleanupExpired()
	}
}

func (cm *ChallengeManager) cleanupExpired() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	now := time.Now().UnixNano() / int64(time.Millisecond) //Current time in milliseconds.

	for challenge, val := range cm.solvedChallenges {
		if val < now {
			delete(cm.solvedChallenges, challenge)
			log.Printf("Challenge %s expired and was removed.\n", challenge)
		}
	}
}
