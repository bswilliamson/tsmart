package tsmart

type command struct {
	Command    uint8
	Subcommand uint16
}

type checksum struct {
	Checksum uint8
}

type basicInfo struct {
	Type     uint16
	ID       uint32
	Name     [32]uint8
	TzOffset uint8
}

type discoveryResponse struct {
	command
	basicInfo
	checksum
}
