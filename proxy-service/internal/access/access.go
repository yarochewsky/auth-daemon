package access

// Store records whitelisted processes that can talk
// to this proxy
type Store interface {
  // AuthorizeProcess authorized newPid. If oldPid > 0, it cleans up oldPid's
  // credentials
  AuthorizeProcess(newPid, oldPid uint32)
  // IsAuthorized returns whether pid is authorized
  IsAuthorized(pid uint32) bool
}

type store struct {
  whitelisted map[uint32]bool
}

// New returns a new Store
func New() Store {
  return &store{
    whitelisted: make(map[uint32]bool),
  }
}

func (s *store) AuthorizeProcess(newPid, oldPid uint32) {
  if oldPid > 0 {
    delete(s.whitelisted, oldPid)
  }
  s.whitelisted[newPid] = true
}

func (s *store) IsAuthorized(pid uint32) bool {
  return s.whitelisted[pid]
}
