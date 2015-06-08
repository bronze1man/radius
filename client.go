package radius

import "sync"

func NewClientList(cs []Client) *ClientList {
	cl := new(ClientList)
	cl.SetHerd(cs)
	return cl
}

// ClientList are list of client allowed to communicate with server
type ClientList struct {
	herd map[string]Client
	sync.RWMutex
}

// Get client from list of clients based on host
func (cls *ClientList) Get(host string) Client {
	cls.RLock()
	defer cls.RUnlock()
	cl, _ := cls.herd[host]
	return cl
}

// Add new client or reset existing client based on host
func (cls *ClientList) AddOrUpdate(cl Client) {
	cls.Lock()
	defer cls.Unlock()
	cls.herd[cl.GetHost()] = cl
}

// Remove client based on host
func (cls *ClientList) Remove(host string) {
	cls.Lock()
	defer cls.Unlock()
	delete(cls.herd, host)
}

// SetHerd reset/initialize the herd of clients
func (cls *ClientList) SetHerd(herd []Client) {
	cls.Lock()
	defer cls.Unlock()
	if cls.herd == nil {
		cls.herd = make(map[string]Client)
	}
	for _, v := range herd {
		cls.herd[v.GetHost()] = v
	}
}

func (cls *ClientList) GetHerd() []Client {
	cls.RLock()
	defer cls.RUnlock()
	herd := make([]Client, len(cls.herd))
	i := 0
	for _, v := range cls.herd {
		herd[i] = v
		i++
	}
	return herd
}

// Client represent a client to connect to radius server
type Client interface {
	// GetHost get the client host
	GetHost() string
	// GetSecret get shared secret
	GetSecret() string
}

// NewClient return new client
func NewClient(host, secret string) Client {
	return &DefaultClient{host, secret}
}

// DefaultClient is default client implementation
type DefaultClient struct {
	Host   string
	Secret string
}

// GetSecret get shared secret
func (cl *DefaultClient) GetSecret() string {
	return cl.Secret
}

// GetHost get the client host
func (cl *DefaultClient) GetHost() string {
	return cl.Host
}
