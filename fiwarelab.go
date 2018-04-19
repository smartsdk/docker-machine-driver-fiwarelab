package fiwarelab

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"

	"github.com/rackspace/gophercloud"
)

type Driver struct {
	*drivers.BaseDriver
	AuthUrl          string
	ActiveTimeout    int
	Insecure         bool
	CaCert           string
	DomainID         string
	DomainName       string
	Username         string
	Password         string
	TenantName       string
	TenantId         string
	Region           string
	AvailabilityZone string
	EndpointType     string
	MachineId        string
	FlavorName       string
	FlavorId         string
	ImageName        string
	ImageId          string
	KeyPairName      string
	NetworkName      string
	NetworkId        string
	UserData         []byte
	PrivateKeyFile   string
	SecurityGroups   []string
	FloatingIpPool   string
	ComputeNetwork   bool
	FloatingIpPoolId string
	IpVersion        int
	ConfigDrive      bool
	client           Client
	// ExistingKey keeps track of whether the key was created by us or we used an existing one. If an existing one was used, we shouldn't delete it when the machine is deleted.
	ExistingKey bool
}

const (
	defaultSSHUser       = "root"
	defaultSSHPort       = 22
	defaultActiveTimeout = 200
)

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_AUTH_URL",
			Name:   "fiwarelab-auth-url",
			Usage:  "Fiwarelab authentication URL",
			Value:  "",
		},
		mcnflag.BoolFlag{
			EnvVar: "FIWARELAB_INSECURE",
			Name:   "fiwarelab-insecure",
			Usage:  "Disable TLS credential checking.",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_CACERT",
			Name:   "fiwarelab-cacert",
			Usage:  "CA certificate bundle to verify against",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_DOMAIN_ID",
			Name:   "fiwarelab-domain-id",
			Usage:  "Fiwarelab domain ID (identity v3 only)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_DOMAIN_NAME",
			Name:   "fiwarelab-domain-name",
			Usage:  "Fiwarelab domain name (identity v3 only)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_USERNAME",
			Name:   "fiwarelab-username",
			Usage:  "Fiwarelab username",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_PASSWORD",
			Name:   "fiwarelab-password",
			Usage:  "Fiwarelab password",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_TENANT_NAME",
			Name:   "fiwarelab-tenant-name",
			Usage:  "Fiwarelab tenant name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_TENANT_ID",
			Name:   "fiwarelab-tenant-id",
			Usage:  "Fiwarelab tenant id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_REGION_NAME",
			Name:   "fiwarelab-region",
			Usage:  "Fiwarelab region name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_AVAILABILITY_ZONE",
			Name:   "fiwarelab-availability-zone",
			Usage:  "Fiwarelab availability zone",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_ENDPOINT_TYPE",
			Name:   "fiwarelab-endpoint-type",
			Usage:  "Fiwarelab endpoint type (adminURL, internalURL or publicURL)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_FLAVOR_ID",
			Name:   "fiwarelab-flavor-id",
			Usage:  "Fiwarelab flavor id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_FLAVOR_NAME",
			Name:   "fiwarelab-flavor-name",
			Usage:  "Fiwarelab flavor name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_IMAGE_ID",
			Name:   "fiwarelab-image-id",
			Usage:  "Fiwarelab image id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_IMAGE_NAME",
			Name:   "fiwarelab-image-name",
			Usage:  "Fiwarelab image name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_KEYPAIR_NAME",
			Name:   "fiwarelab-keypair-name",
			Usage:  "Fiwarelab keypair to use to SSH to the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_NETWORK_ID",
			Name:   "fiwarelab-net-id",
			Usage:  "Fiwarelab network id the machine will be connected on",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_PRIVATE_KEY_FILE",
			Name:   "fiwarelab-private-key-file",
			Usage:  "Private keyfile to use for SSH (absolute path)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_USER_DATA_FILE",
			Name:   "fiwarelab-user-data-file",
			Usage:  "File containing an fiwarelab userdata script",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_NETWORK_NAME",
			Name:   "fiwarelab-net-name",
			Usage:  "Fiwarelab network name the machine will be connected on",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_SECURITY_GROUPS",
			Name:   "fiwarelab-sec-groups",
			Usage:  "Fiwarelab comma separated security groups for the machine",
			Value:  "",
		},
		mcnflag.BoolFlag{
			EnvVar: "FIWARELAB_NOVA_NETWORK",
			Name:   "fiwarelab-nova-network",
			Usage:  "Use the nova networking services instead of neutron.",
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_FLOATINGIP_POOL",
			Name:   "fiwarelab-floatingip-pool",
			Usage:  "Fiwarelab floating IP pool to get an IP from to assign to the instance",
			Value:  "",
		},
		mcnflag.IntFlag{
			EnvVar: "FIWARELAB_IP_VERSION",
			Name:   "fiwarelab-ip-version",
			Usage:  "Fiwarelab version of IP address assigned for the machine",
			Value:  4,
		},
		mcnflag.StringFlag{
			EnvVar: "FIWARELAB_SSH_USER",
			Name:   "fiwarelab-ssh-user",
			Usage:  "Fiwarelab SSH user",
			Value:  defaultSSHUser,
		},
		mcnflag.IntFlag{
			EnvVar: "FIWARELAB_SSH_PORT",
			Name:   "fiwarelab-ssh-port",
			Usage:  "Fiwarelab SSH port",
			Value:  defaultSSHPort,
		},
		mcnflag.IntFlag{
			EnvVar: "FIWARELAB_ACTIVE_TIMEOUT",
			Name:   "fiwarelab-active-timeout",
			Usage:  "Fiwarelab active timeout",
			Value:  defaultActiveTimeout,
		},
		mcnflag.BoolFlag{
			EnvVar: "FIWARELAB_CONFIG_DRIVE",
			Name:   "fiwarelab-config-drive",
			Usage:  "Enables the Fiwarelab config drive for the instance",
		},
	}
}

func NewDriver(hostName, storePath string) drivers.Driver {
	return NewDerivedDriver(hostName, storePath)
}

func NewDerivedDriver(hostName, storePath string) *Driver {
	return &Driver{
		client:        &GenericClient{},
		ActiveTimeout: defaultActiveTimeout,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			SSHPort:     defaultSSHPort,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

func (d *Driver) SetClient(client Client) {
	d.client = client
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "fiwarelab"
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.AuthUrl = flags.String("fiwarelab-auth-url")
	d.ActiveTimeout = flags.Int("fiwarelab-active-timeout")
	d.Insecure = flags.Bool("fiwarelab-insecure")
	d.CaCert = flags.String("fiwarelab-cacert")
	d.DomainID = flags.String("fiwarelab-domain-id")
	d.DomainName = flags.String("fiwarelab-domain-name")
	d.Username = flags.String("fiwarelab-username")
	d.Password = flags.String("fiwarelab-password")
	d.TenantName = flags.String("fiwarelab-tenant-name")
	d.TenantId = flags.String("fiwarelab-tenant-id")
	d.Region = flags.String("fiwarelab-region")
	d.AvailabilityZone = flags.String("fiwarelab-availability-zone")
	d.EndpointType = flags.String("fiwarelab-endpoint-type")
	d.FlavorId = flags.String("fiwarelab-flavor-id")
	d.FlavorName = flags.String("fiwarelab-flavor-name")
	d.ImageId = flags.String("fiwarelab-image-id")
	d.ImageName = flags.String("fiwarelab-image-name")
	d.NetworkId = flags.String("fiwarelab-net-id")
	d.NetworkName = flags.String("fiwarelab-net-name")
	if flags.String("fiwarelab-sec-groups") != "" {
		d.SecurityGroups = strings.Split(flags.String("fiwarelab-sec-groups"), ",")
	}
	d.FloatingIpPool = flags.String("fiwarelab-floatingip-pool")
	d.IpVersion = flags.Int("fiwarelab-ip-version")
	d.ComputeNetwork = flags.Bool("fiwarelab-nova-network")
	d.SSHUser = flags.String("fiwarelab-ssh-user")
	d.SSHPort = flags.Int("fiwarelab-ssh-port")
	d.ExistingKey = flags.String("fiwarelab-keypair-name") != ""
	d.KeyPairName = flags.String("fiwarelab-keypair-name")
	d.PrivateKeyFile = flags.String("fiwarelab-private-key-file")
	d.ConfigDrive = flags.Bool("fiwarelab-config-drive")

	if flags.String("fiwarelab-user-data-file") != "" {
		userData, err := ioutil.ReadFile(flags.String("fiwarelab-user-data-file"))
		if err == nil {
			d.UserData = userData
		} else {
			return err
		}
	}

	d.SetSwarmConfigFromFlags(flags)

	return d.checkConfig()
}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

func (d *Driver) GetIP() (string, error) {
	if d.IPAddress != "" {
		return d.IPAddress, nil
	}

	log.Debug("Looking for the IP address...", map[string]string{"MachineId": d.MachineId})

	if err := d.initCompute(); err != nil {
		return "", err
	}

	addressType := Fixed
	if d.FloatingIpPool != "" {
		addressType = Floating
	}

	// Looking for the IP address in a retry loop to deal with OpenStack latency
	for retryCount := 0; retryCount < 200; retryCount++ {
		addresses, err := d.client.GetInstanceIPAddresses(d)
		if err != nil {
			return "", err
		}
		for _, a := range addresses {
			if a.AddressType == addressType && a.Version == d.IpVersion {
				return a.Address, nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return "", fmt.Errorf("No IP found for the machine")
}

func (d *Driver) GetState() (state.State, error) {
	log.Debug("Get status for OpenStack instance...", map[string]string{"MachineId": d.MachineId})
	if err := d.initCompute(); err != nil {
		return state.None, err
	}

	s, err := d.client.GetInstanceState(d)
	if err != nil {
		return state.None, err
	}

	log.Debug("State for OpenStack instance", map[string]string{
		"MachineId": d.MachineId,
		"State":     s,
	})

	switch s {
	case "ACTIVE":
		return state.Running, nil
	case "PAUSED":
		return state.Paused, nil
	case "SUSPENDED":
		return state.Saved, nil
	case "SHUTOFF":
		return state.Stopped, nil
	case "BUILDING":
		return state.Starting, nil
	case "ERROR":
		return state.Error, nil
	}
	return state.None, nil
}

func (d *Driver) Create() error {
	if err := d.resolveIds(); err != nil {
		return err
	}
	if d.KeyPairName != "" {
		if err := d.loadSSHKey(); err != nil {
			return err
		}
	} else {
		d.KeyPairName = fmt.Sprintf("%s-%s", d.MachineName, mcnutils.GenerateRandomID())
		if err := d.createSSHKey(); err != nil {
			return err
		}
	}
	if err := d.createMachine(); err != nil {
		return err
	}
	if err := d.waitForInstanceActive(); err != nil {
		return err
	}
	if d.FloatingIpPool != "" {
		if err := d.assignFloatingIP(); err != nil {
			return err
		}
	}
	if err := d.lookForIPAddress(); err != nil {
		return err
	}
	return nil
}

func (d *Driver) Start() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StartInstance(d)
}

func (d *Driver) Stop() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.StopInstance(d)
}

func (d *Driver) Restart() error {
	if err := d.initCompute(); err != nil {
		return err
	}

	return d.client.RestartInstance(d)
}

func (d *Driver) Kill() error {
	return d.Stop()
}

func (d *Driver) Remove() error {
	log.Debug("deleting instance...", map[string]string{"MachineId": d.MachineId})
	log.Info("Deleting OpenStack instance...")
	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.DeleteInstance(d); err != nil {
		if gopherErr, ok := err.(*gophercloud.UnexpectedResponseCodeError); ok {
			if gopherErr.Actual == http.StatusNotFound {
				log.Warn("Remote instance does not exist, proceeding with removing local reference")
			} else {
				return err
			}
		} else {
			return err
		}
	}
	if !d.ExistingKey {
		log.Debug("deleting key pair...", map[string]string{"Name": d.KeyPairName})
		if err := d.client.DeleteKeyPair(d, d.KeyPairName); err != nil {
			return err
		}
	}
	return nil
}

const (
	errorMandatoryEnvOrOption    string = "%s must be specified either using the environment variable %s or the CLI option %s"
	errorMandatoryOption         string = "%s must be specified using the CLI option %s"
	errorExclusiveOptions        string = "Either %s or %s must be specified, not both"
	errorBothOptions             string = "Both %s and %s must be specified"
	errorMandatoryTenantNameOrID string = "Tenant id or name must be provided either using one of the environment variables FIWARELAB_TENANT_ID and FIWARELAB_TENANT_NAME or one of the CLI options --fiwarelab-tenant-id and --fiwarelab-tenant-name"
	errorWrongEndpointType       string = "Endpoint type must be 'publicURL', 'adminURL' or 'internalURL'"
	errorUnknownFlavorName       string = "Unable to find flavor named %s"
	errorUnknownImageName        string = "Unable to find image named %s"
	errorUnknownNetworkName      string = "Unable to find network named %s"
	errorUnknownTenantName       string = "Unable to find tenant named %s"
)

func (d *Driver) checkConfig() error {
	if d.AuthUrl == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Authentication URL", "FIWARELAB_AUTH_URL", "--fiwarelab-auth-url")
	}
	if d.Username == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Username", "FIWARELAB_USERNAME", "--fiwarelab-username")
	}
	if d.Password == "" {
		return fmt.Errorf(errorMandatoryEnvOrOption, "Password", "FIWARELAB_PASSWORD", "--fiwarelab-password")
	}
	if d.TenantName == "" && d.TenantId == "" {
		return fmt.Errorf(errorMandatoryTenantNameOrID)
	}

	if d.FlavorName == "" && d.FlavorId == "" {
		return fmt.Errorf(errorMandatoryOption, "Flavor name or Flavor id", "--fiwarelab-flavor-name or --fiwarelab-flavor-id")
	}
	if d.FlavorName != "" && d.FlavorId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Flavor name", "Flavor id")
	}

	if d.ImageName == "" && d.ImageId == "" {
		return fmt.Errorf(errorMandatoryOption, "Image name or Image id", "--fiwarelab-image-name or --fiwarelab-image-id")
	}
	if d.ImageName != "" && d.ImageId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Image name", "Image id")
	}

	if d.NetworkName != "" && d.NetworkId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Network name", "Network id")
	}
	if d.EndpointType != "" && (d.EndpointType != "publicURL" && d.EndpointType != "adminURL" && d.EndpointType != "internalURL") {
		return fmt.Errorf(errorWrongEndpointType)
	}
	if (d.KeyPairName != "" && d.PrivateKeyFile == "") || (d.KeyPairName == "" && d.PrivateKeyFile != "") {
		return fmt.Errorf(errorBothOptions, "KeyPairName", "PrivateKeyFile")
	}
	return nil
}

func (d *Driver) resolveIds() error {
	if d.NetworkName != "" && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err
		}

		networkID, err := d.client.GetNetworkID(d)

		if err != nil {
			return err
		}

		if networkID == "" {
			return fmt.Errorf(errorUnknownNetworkName, d.NetworkName)
		}

		d.NetworkId = networkID
		log.Debug("Found network id using its name", map[string]string{
			"Name": d.NetworkName,
			"ID":   d.NetworkId,
		})
	}

	if d.FlavorName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		flavorID, err := d.client.GetFlavorID(d)

		if err != nil {
			return err
		}

		if flavorID == "" {
			return fmt.Errorf(errorUnknownFlavorName, d.FlavorName)
		}

		d.FlavorId = flavorID
		log.Debug("Found flavor id using its name", map[string]string{
			"Name": d.FlavorName,
			"ID":   d.FlavorId,
		})
	}

	if d.ImageName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		imageID, err := d.client.GetImageID(d)

		if err != nil {
			return err
		}

		if imageID == "" {
			return fmt.Errorf(errorUnknownImageName, d.ImageName)
		}

		d.ImageId = imageID
		log.Debug("Found image id using its name", map[string]string{
			"Name": d.ImageName,
			"ID":   d.ImageId,
		})
	}

	if d.FloatingIpPool != "" && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err
		}
		f, err := d.client.GetFloatingIPPoolID(d)

		if err != nil {
			return err
		}

		if f == "" {
			return fmt.Errorf(errorUnknownNetworkName, d.FloatingIpPool)
		}

		d.FloatingIpPoolId = f
		log.Debug("Found floating IP pool id using its name", map[string]string{
			"Name": d.FloatingIpPool,
			"ID":   d.FloatingIpPoolId,
		})
	}

	if d.TenantName != "" && d.TenantId == "" {
		if err := d.initIdentity(); err != nil {
			return err
		}
		tenantId, err := d.client.GetTenantID(d)

		if err != nil {
			return err
		}

		if tenantId == "" {
			return fmt.Errorf(errorUnknownTenantName, d.TenantName)
		}

		d.TenantId = tenantId
		log.Debug("Found tenant id using its name", map[string]string{
			"Name": d.TenantName,
			"ID":   d.TenantId,
		})
	}

	return nil
}

func (d *Driver) initCompute() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitComputeClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initIdentity() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitIdentityClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) initNetwork() error {
	if err := d.client.Authenticate(d); err != nil {
		return err
	}
	if err := d.client.InitNetworkClient(d); err != nil {
		return err
	}
	return nil
}

func (d *Driver) loadSSHKey() error {
	log.Debug("Loading Key Pair", d.KeyPairName)
	if err := d.initCompute(); err != nil {
		return err
	}
	log.Debug("Loading Private Key from", d.PrivateKeyFile)
	privateKey, err := ioutil.ReadFile(d.PrivateKeyFile)
	if err != nil {
		return err
	}
	publicKey, err := d.client.GetPublicKey(d.KeyPairName)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.privateSSHKeyPath(), privateKey, 0600); err != nil {
		return err
	}
	if err := ioutil.WriteFile(d.publicSSHKeyPath(), publicKey, 0600); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createSSHKey() error {
	sanitizeKeyPairName(&d.KeyPairName)
	log.Debug("Creating Key Pair...", map[string]string{"Name": d.KeyPairName})
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err
	}
	publicKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}

	if err := d.initCompute(); err != nil {
		return err
	}
	if err := d.client.CreateKeyPair(d, d.KeyPairName, string(publicKey)); err != nil {
		return err
	}
	return nil
}

func (d *Driver) createMachine() error {
	log.Debug("Creating OpenStack instance...", map[string]string{
		"FlavorId": d.FlavorId,
		"ImageId":  d.ImageId,
	})

	if err := d.initCompute(); err != nil {
		return err
	}
	instanceID, err := d.client.CreateInstance(d)
	if err != nil {
		return err
	}
	d.MachineId = instanceID
	return nil
}

func (d *Driver) assignFloatingIP() error {
	var err error

	if d.ComputeNetwork {
		err = d.initCompute()
	} else {
		err = d.initNetwork()
	}

	if err != nil {
		return err
	}

	ips, err := d.client.GetFloatingIPs(d)
	if err != nil {
		return err
	}

	var floatingIP *FloatingIP

	log.Debugf("Looking for an available floating IP", map[string]string{
		"MachineId": d.MachineId,
		"Pool":      d.FloatingIpPool,
	})

	for _, ip := range ips {
		if ip.PortId == "" {
			log.Debug("Available floating IP found", map[string]string{
				"MachineId": d.MachineId,
				"IP":        ip.Ip,
			})
			floatingIP = &ip
			break
		}
	}

	if floatingIP == nil {
		floatingIP = &FloatingIP{}
		log.Debug("No available floating IP found. Allocating a new one...", map[string]string{"MachineId": d.MachineId})
	} else {
		log.Debug("Assigning floating IP to the instance", map[string]string{"MachineId": d.MachineId})
	}

	if err := d.client.AssignFloatingIP(d, floatingIP); err != nil {
		return err
	}
	d.IPAddress = floatingIP.Ip
	return nil
}

func (d *Driver) waitForInstanceActive() error {
	log.Debug("Waiting for the OpenStack instance to be ACTIVE...", map[string]string{"MachineId": d.MachineId})
	if err := d.client.WaitForInstanceStatus(d, "ACTIVE"); err != nil {
		return err
	}
	return nil
}

func (d *Driver) lookForIPAddress() error {
	ip, err := d.GetIP()
	if err != nil {
		return err
	}
	d.IPAddress = ip
	log.Debug("IP address found", map[string]string{
		"IP":        ip,
		"MachineId": d.MachineId,
	})
	return nil
}

func (d *Driver) privateSSHKeyPath() string {
	return d.GetSSHKeyPath()
}

func (d *Driver) publicSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"
}

func sanitizeKeyPairName(s *string) {
	*s = strings.Replace(*s, ".", "_", -1)
}
