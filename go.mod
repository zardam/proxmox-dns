module zardam/proxmox-dns

go 1.16

replace github.com/Telmate/proxmox-api-go => github.com/zardam/proxmox-api-go v0.0.0-20210317225550-044a015405e2

require (
	github.com/Telmate/proxmox-api-go v0.0.0-20210311000442-2c76bbc1abc4
	github.com/miekg/dns v1.1.40
)
