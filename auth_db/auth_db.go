// Auth db is a map with data related to authenticated clients
// The char and map server uses it to authenticate incoming connection requests with this server
package auth_db

import "sync"

// Mutex
var mutex = &sync.Mutex{}

// Structure
type AuthDB struct {
	Account_id int
	Login_id1  uint32
	Login_id2  uint32
	Sex        uint8
	Version    uint32
	Clienttype uint8
}

// Map
var hashtable = make(map[int]*AuthDB)

// Register structure to auth_db map
func (a *AuthDB) Register(key int) {
	mutex.Lock()
	hashtable[key] = a
	mutex.Unlock()
	return
}

// Get from auth_Db
func Get(key int) *AuthDB {
	return hashtable[key]
}

// Delete from auth_Db
func Delete(key int) {
	mutex.Lock()
	delete(hashtable, key)
	mutex.Unlock()
	return
}
