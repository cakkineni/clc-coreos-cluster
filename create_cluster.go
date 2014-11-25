package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	//"net/http/httputil"
	//"flag"
	"math/rand"
	"os"
	"time"
)

var (
	clcApi,
	dhcpServerAlias,
	coreosServerAlias string = "https://api.tier3.com/rest", "DHCP", "COREOS"
	letters = []rune("abcdefghijklmnopqrstuvwxyz")
	createdDhcpName,
	location,
	networkName,
	groupName,
	apiKey,
	apiPassword,
	accountAlias,
	serverPassword string
	groupId,
	serverCount int
)

func main() {

	login()

	groupId = createGroup()

	networkName = getNetwork()

	createdDhcpName = createDhcpServer()

	_, ipResp := addPublicIp()

	for i := 0; i < serverCount; i++ {
		coreosServer := createCoreosServer()
		resizeDisk(coreosServer)
		fmt.Println("\nCoreOS Server Created: %s", coreosServer)
	}

	logout()

	fmt.Printf("\n\nLogin to Cluster Manager with: root@%s, using password: %s", ipResp, serverPassword)

	fmt.Scanln()
}

func init() {
	groupName = os.Getenv("CLUSTER_NAME")
	serverCount, _ = strconv.Atoi(os.Getenv("NODE_COUNT"))
	apiKey = os.Getenv("API_KEY")
	apiPassword = os.Getenv("API_PASSWORD")
	location = os.Getenv("DATA_CENTER")
	networkName = os.Getenv("NETWORK_NAME")
	serverPassword = fmt.Sprintf("%sA!", randSeq(8))

	if apiKey == "" || apiPassword == "" || groupName == "" || serverCount == 0 || location == "" || networkName == "" {
		panic("Missing Params")
	}

	groupName = fmt.Sprintf("%s-%s", groupName, randSeq(4))

}

func login() {
	println("\nLogging in....")

	var postData = struct {
		APIKEY   string
		Password string
	}{apiKey, apiPassword}

	resp := postJsonData("/auth/logon", postData)

	var status struct {
		success bool
	}

	json.Unmarshal([]byte(resp), &status)
	if !status.success {
		panic("Login Failed, Please check credentials.")
	}
}

func logout() {
	println("\nLogging out...")
	httpClient.Get(clcApi + "/auth/logout")
}

func createGroup() int {
	fmt.Printf("\nCreating Cluster Group in Data Center %s with name: %s", location, groupName)
	var acctLocation = struct {
		Location string
	}{location}

	var parentId int
	var resp = postJsonData("/Group/GetGroups/json", acctLocation)

	var hwGroups struct {
		AccountAlias   string
		HardwareGroups []struct {
			ID            int
			Name          string
			IsSystemGroup bool
		}
	}

	json.Unmarshal([]byte(resp), &hwGroups)

	accountAlias = hwGroups.AccountAlias

	for _, group := range hwGroups.HardwareGroups {
		if strings.Contains(group.Name, location) && group.IsSystemGroup {
			parentId = group.ID
			break
		}
	}

	var postData = struct {
		AccountAlias string
		ParentID     int
		Name         string
		Description  string
	}{accountAlias, parentId, groupName, "CoreOS Cluster"}

	var respNewGroup = postJsonData("/Group/CreateHardwareGroup/json", postData)
	var newGroup struct {
		Group struct {
			ID int
		}
	}

	json.Unmarshal([]byte(respNewGroup), &newGroup)
	return newGroup.Group.ID
}

func randSeq(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func getNetwork() string {
	println("\n\nGetting Network Details...")
	var retValue = ""
	var location = struct {
		Location string
	}{location}

	var resp = postJsonData("/Network/GetAccountNetworks/JSON", location)

	var networks struct {
		Networks []struct {
			Name        string
			Description string
		}
	}

	json.Unmarshal([]byte(resp), &networks)

	for _, group := range networks.Networks {
		if strings.Contains(group.Description, networkName) {
			retValue = group.Description
			break
		}
	}
	return retValue
}

func deployBlueprintServer(params interface{}) (BlueprintRequestStatus, string) {
	var resp, serverName string
	var reqStatus BlueprintRequestStatus
	resp = postJsonData("/Blueprint/DeployBlueprint/", params)
	serverName = ""
	json.Unmarshal([]byte(resp), &reqStatus)
	if reqStatus.Success {
		for {
			status := getDeploymentStatus(reqStatus.RequestID)
			if status.Success {
				serverName = "Test Me"
				break
			}
			fmt.Print("  .")
			time.Sleep(5000 * time.Millisecond)
		}
	}
	return reqStatus, serverName
}

func createDhcpServer() string {
	println("\nCreating DHCP Server")
	params := BlueprintData{
		ID:            1421,
		LocationAlias: location,
		Parameters: []BlueprintParameters{
			{"T3.BuildServerTask.Password", serverPassword},
			{"T3.BuildServerTask.GroupID", strconv.Itoa(groupId)},
			{"T3.BuildServerTask.Network", networkName},
			{"T3.BuildServerTask.PrimaryDNS", "4.4.2.2"},
			{"T3.BuildServerTask.SecondaryDNS", "4.4.2.3"},
			{"79d24724-4335-4c7d-b8ed-2fa59c5e6f97.Alias", dhcpServerAlias},
		}}
	_, serverName := deployBlueprintServer(params)
	return serverName
}

func createCoreosServer() string {
	println("\nCreating CoreOS Server")
	params := BlueprintData{
		ID:            1422,
		LocationAlias: location,
		Parameters: []BlueprintParameters{
			{"TemplateID", "1422"},
			{"T3.BuildServerTask.Password", serverPassword},
			{"T3.BuildServerTask.GroupID", strconv.Itoa(groupId)},
			{"T3.BuildServerTask.Network", networkName},
			{"T3.BuildServerTask.PrimaryDNS", "4.4.2.2"},
			{"T3.BuildServerTask.SecondaryDNS", "4.4.2.3"},
			{"5c69284a-2398-4e5a-8172-57bc44f4a6c9.Alias", coreosServerAlias},
			{"fee73a61-be29-458a-aaa7-41e5e48aec2b.TaskServer", createdDhcpName},
			//{ "fee73a61-be29-458a-aaa7-41e5e48aec2b.T3.CoreOS.SshPublicKey", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTmIY/i5x5tjmnZLDORIC+/lEmKzGjjj+5S1I1dAQxO923ionVRVepzKhZWlbGa+IfyhoUhCQABXjJQlcbWGbCyDs0m+w2eqB9WwJQRD9zhl+nMv2B173f6EqmxmiRPENQaeXSCLb244xU2zmA7p8h3oPkDD+EonNP/dbfqfkAKq3dQCKNqCRzcMVTgP+0d0UC5I+lhp0mRe6/AhBWwBzdkmHe0N1u5fRgKxIB30mxXMoIv5AkuHuYSyDQRbGPsciL6sa6qhpXMMEpTlBtEO87EqufgoNj1oqYbSGs4qMEjFNVu7CAK8sDbJ+IVvLLbodzqn/mzZ66CfAnJzv797aN cakkineni@Chaitanyas-MacBook-Air.local"},
		}}
	_, serverName := deployBlueprintServer(params)
	return serverName
}

func resizeDisk(coreosServer string) {
	fmt.Printf("\nResizing %s", coreosServer)
	params := fmt.Sprintf("{\"AccountAlias\": \"%s\", \"Name\": \"%s\", \"ScsiBusID\": \"0\", \"ScsiDeviceID\": \"2\", \"ResizeGuestDisk\": true, \"NewSizeGB\": 50 }", accountAlias, coreosServer)
	postJsonData("Server/ResizeDisk/json", params)
}

func addPublicIp() (bool, string) {
	println("\nAdding Public IP Address....")
	var status bool
	var ipAddress string
	var postData = struct {
		AccountAlias   string
		ServerName     string
		ServerPassword string
		AllowSSH       bool
	}{accountAlias, createdDhcpName, serverPassword, true}

	resp := postJsonData("/Network/AddPublicIPAddress/json", postData)

	var reqStatus BlueprintRequestStatus
	json.Unmarshal([]byte(resp), &reqStatus)

	if !reqStatus.Success {
		fmt.Println("\n%s", resp)
		status = false
		ipAddress = ""
		return status, ipAddress
	}

	for {
		status := getDeploymentStatus(reqStatus.RequestID)
		if status.Success {
			break
		}
		fmt.Print("  .")
		time.Sleep(5000 * time.Millisecond)
	}
	return true, ipAddress
}

func getDeploymentStatus(reqId int) BlueprintRequestStatus {
	var postData = struct {
		RequestID     int
		LocationAlias string
	}{reqId, location}

	var reqStatus BlueprintRequestStatus
	resp := postJsonData("/Blueprint/GetBlueprintStatus/json", postData)
	fmt.Printf("\n%s", resp)
	json.Unmarshal([]byte(resp), &reqStatus)
	return reqStatus
}

type BlueprintData struct {
	ID            int
	LocationAlias string
	Parameters    []BlueprintParameters
}

type BlueprintParameters struct {
	Name  string
	Value string
}

type BlueprintRequestStatus struct {
	RequestID int
	Success   bool
}
