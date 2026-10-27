//go:build windows

package winsecurity

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RequireCurrentOwner rejects shared objects owned by another account before
// any agent data is read or written through them.
func RequireCurrentOwner(handle windows.Handle) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if !sameOwner(owner, user.User.Sid) {
		return errors.New("shared memory owner is not the current user")
	}
	return nil
}

func sameOwner(owner, user *windows.SID) bool {
	return owner != nil && user != nil && owner.Equals(user)
}

// CreateTemp installs a protected DACL at creation time. Unix mode
// bits do not restrict Windows ACLs, including in shared parent directories.
func CreateTemp(dir, prefix string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if user.User.Sid == nil {
		return nil, errors.New("token has no user SID")
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	name := filepath.Join(dir, prefix+rand.Text()+".tmp")
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	attrs := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		&attrs, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}
