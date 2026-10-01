package drivemap

type Mapper interface {
	Map(localDir, mountPoint string) error

	Unmap(mountPoint string) error

	IsMapped(mountPoint string) bool
}
