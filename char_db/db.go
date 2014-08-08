// Char db
// Contains a table with all connected char-servers
package char_db

import "sync"

// Mutex
var mutex = &sync.Mutex{}

// Structure
type CharDB struct {
	Name  string //char-serv name
	Ip    uint32 //char-serv IP
	Port  uint16 //char-serv rt
	Users uint16 // user count on this server
	Type  uint16 // 0=normal, 1=maintenance, 2=over 18, 3=paying, 4=P2P
	New   uint16 // should display as 'new'?
}

// Map
var hashtable = make(map[int]*CharDB)

// Register structure to auth_db map
func (c *CharDB) Register(key int) {
	mutex.Lock()
	hashtable[key] = c
	mutex.Unlock()
	return
}

// Get from auth_Db
func Get(key int) *CharDB {
	return hashtable[key]
}

// Delete from auth_Db
func Delete(key int) {
	mutex.Lock()
	delete(hashtable, key)
	mutex.Unlock()
	return
}
