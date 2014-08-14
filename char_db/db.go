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

// Map with all registerd char-servers
var table = make(map[int]*CharDB)

// Register structure to auth_db map
func (c *CharDB) Register(key int) {
	mutex.Lock()
	table[key] = c
	mutex.Unlock()
	return
}

// Retrive from char_db
func Get(key int) (entry *CharDB, ok bool) {
	entry, ok = table[key]
	return
}

// Return an list with all char-servers
func List() map[int]*CharDB {
	return table
}

// Delete from char_db
func Delete(key int) {
	mutex.Lock()
	delete(table, key)
	mutex.Unlock()
	return
}
