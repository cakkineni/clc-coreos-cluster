package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	//"net/http/httputil"
	//"flag"
	"crypto/tls"
	"crypto/x509"
	"math/rand"
	"os"
	"time"
)

var (
	httpClient                                                                                                  = &http.Client{}
	clcApi, dhcpServerAlias, coreosServerAlias                                                           string = "https://api.tier3.com/rest", "DHCP", "COREOS"
	letters                                                                                                     = []rune("abcdefghijklmnopqrstuvwxyz")
	createdDhcpName, location, networkName, groupName, apiKey, apiPassword, accountAlias, serverPassword string
	groupId, serverCount                                                                                 int
	pool                                                                                                 *x509.CertPool
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
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(pemCerts)
	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	jar := &localCookieJar{}
	jar.jar = make(map[string][]*http.Cookie)
	httpClient.Jar = jar

	groupName = os.Getenv("CLUSTER_NAME")
	serverCount, _ = strconv.Atoi(os.Getenv("NODE_COUNT"))
	apiKey = os.Getenv("API_KEY")
	apiPassword = os.Getenv("API_PASSWORD")
	location = os.Getenv("DATA_CENTER")
	networkName = os.Getenv("NETWORK_NAME")
	serverPassword = fmt.Sprintf("%sA!", randSeq(8))
	if groupName == "" {
		groupName = randSeq(8)
	} else {
		groupName = fmt.Sprintf("%s-%s", groupName, randSeq(4))
	}

	if apiKey == "" || apiPassword == "" || groupName == "" || serverCount == 0 || location == "" || networkName == "" {
		panic("Missing Params")
	}

}

func login() {
	println("\nLogging in....")
	//curl -D $cookie_file -H "Accept: application/json" -H "Content-type: application/json" -X POST  -d $creds $api_server/auth/logon
	resp := postJsonData("/auth/logon", fmt.Sprintf("{'APIKEY': '%s','Password': '%s' }", apiKey, apiPassword))
	fmt.Printf("\n\nResponse:%s", resp)
}

func logout() {
	println("\nLogging out...")
	httpClient.Get(clcApi + "/auth/logout")
}

func createGroup() int {
	fmt.Printf("\nCreating Cluster Group in Data Center %s with name: %s", location, groupName)
	//curl -b $cookie_file -o $location/groups -X GET $api_server/Group/GetGroups/json?Location=$location
	var resp = postJsonData("/Group/GetGroups/json", fmt.Sprintf("{ \"Location\": \"%s\"}", location))

	var hwGroups struct {
		AccountAlias   string
		HardwareGroups []struct {
			ID            int
			Name          string
			IsSystemGroup bool
		}
	}

	var new_group struct {
		Group struct {
			ID int
		}
	}

	var parentId int

	json.Unmarshal([]byte(resp), &hwGroups)
	accountAlias = hwGroups.AccountAlias
	for _, group := range hwGroups.HardwareGroups {
		if strings.Contains(group.Name, location) && group.IsSystemGroup {
			parentId = group.ID
			break
		}
	}

	var resp_new_group = postJsonData("/Group/CreateHardwareGroup/json", fmt.Sprintf("{\"AccountAlias\": \"%s\",\"ParentID\": \"%d\",\"Name\": \"%s\",\"Description\": \"CoreOS Cluster\"}", accountAlias, parentId, groupName))

	json.Unmarshal([]byte(resp_new_group), &new_group)
	return new_group.Group.ID
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
	//curl -b $cookie_file -o $location/networks -H "Content-type: application/json"  -X POST -d "{'Location':'$location'}" $api_server/Network/GetAccountNetworks/JSON
	var retValue = ""
	var resp = postJsonData("/Network/GetAccountNetworks/JSON", fmt.Sprintf("{ \"Location\": \"%s\"}", location))

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

func deployBlueprintServer(params string) (string, string) {
	var resp, serverName string
	var reqStatus BlueprintRequestStatus

	resp = postJsonData("/Blueprint/DeployBlueprint/", params)
	serverName = ""

	fmt.Printf("Server Response: %s", resp)

	json.Unmarshal([]byte(resp), &reqStatus)

	if reqStatus.Success {

		type RequestStatus struct {
			PercentComplete int
			Servers         []string
		}

		for {
			status := get_deployment_status(reqStatus.RequestID)
			var reqStatus RequestStatus
			json.Unmarshal([]byte(status), &reqStatus)
			if strings.Contains(status, "Succeeded") {
				serverName = reqStatus.Servers[0]
				break
			}
			//fmt.Printf("\t%d", reqStatus.PercentComplete)
			fmt.Print("  .")
			time.Sleep(2000 * time.Millisecond)
		}
	}
	return resp, serverName
}

func createDhcpServer() string {
	println("\nCreating DHCP Server")
	//#{"ID":1421,"Parameters":[{"Name":"T3.BuildServerTask.Password","Type":4,"Required":true,"Default":null,"Regex":null,"Options":null},{"Name":"T3.BuildServerTask.GroupID","Type":10,"Required":true,"Default":null,"Regex":null,"Options":null},{"Name":"T3.BuildServerTask.Network","Type":1,"Required":true,"Default":null,"Regex":null,"Options":null},{"Name":"T3.BuildServerTask.PrimaryDNS","Type":7,"Required":true,"Default":"${T3.PrimaryDNS}","Regex":null,"Options":null},{"Name":"T3.BuildServerTask.SecondaryDNS","Type":7,"Required":false,"Default":"${T3.SecondaryDNS}","Regex":null,"Options":null},{"Name":"T3.BuildServerTask.HardwareType","Type":3,"Required":true,"Default":"Standard","Regex":null,"Options":[{"Name":"Enterprise","Value":"Enterprise"},{"Name":"Standard (default)","Value":"Standard"},{"Name":"Hyperscale","Value":"Hyperscale"}]},{"Name":"T3.BuildServerTask.AntiAffinityPoolId","Type":13,"Required":false,"Default":null,"Regex":null,"Options":null},{"Name":"T3.BuildServerTask.ServiceLevel","Type":3,"Required":false,"Default":"Standard","Regex":null,"Options":[{"Name":"Premium","Value":"Premium"},{"Name":"Standard (default)","Value":"Standard"}]},{"Name":"79d24724-4335-4c7d-b8ed-2fa59c5e6f97.Alias","Type":11,"Required":true,"Default":"DHCP","Regex":null,"Options":null}],"Success":true,"Message":"Success","StatusCode":0}
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
	//curl -b $cookie_file -H "Accept: application/json" -H "Content-type: application/json" -X POST  -d $dhcp_params $api_server/Blueprint/DeployBlueprint/
	paramsStr, _ := json.Marshal(params)
	_, serverName := deployBlueprintServer(string(paramsStr))

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
	paramsStr, _ := json.Marshal(params)
	_, serverName := deployBlueprintServer(string(paramsStr))

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
	reqData := fmt.Sprintf("{\"AccountAlias\":\"%s\", \"ServerName\": \"%s\",\"ServerPassword\": \"%s\",\"AllowSSH\": true}", accountAlias, createdDhcpName, serverPassword)
	resp := postJsonData("/Network/AddPublicIPAddress/json", reqData)
	var reqStatus BlueprintRequestStatus

	json.Unmarshal([]byte(resp), &reqStatus)

	if !reqStatus.Success {
		fmt.Println("\n%s", resp)
		status = false
		ipAddress = ""
		return status, ipAddress
	}

	for {
		status := get_deployment_status(reqStatus.RequestID)
		var reqStatus BlueprintRequestStatus
		json.Unmarshal([]byte(status), &reqStatus)
		if strings.Contains(status, "Succeeded") {
			break
		}
		fmt.Print("  .")
		time.Sleep(5000 * time.Millisecond)
	}
	return true, ipAddress
}

func get_deployment_status(req_id int) string {
	reqData := fmt.Sprintf("{  \"RequestID\": \"%s\",\"LocationAlias\": \"%s\"}", strconv.Itoa(req_id), location)
	resp := postJsonData("/Blueprint/GetBlueprintStatus/json", reqData)
	return resp
}

func postJsonData(api_end_point string, postData string) string {
	url1 := clcApi + api_end_point
	reqData := strings.NewReader(postData)
	req, err := http.NewRequest("POST", url1, reqData)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)

	if err != nil {
		fmt.Printf("\n\nError : %s", err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Fatal(err)
	}

	//debug(httputil.DumpRequest(req, true))
	//fmt.Printf("\n%s\n", api_end_point)
	//debug(httputil.DumpResponse(resp, true))

	return fmt.Sprintf("%s", body)
}

func debug(data []byte, err error) {
	if err == nil {
		fmt.Printf("%s\n\n", data)
	} else {
		log.Fatalf("%s\n\n", err)
	}
}

type localCookieJar struct {
	jar map[string][]*http.Cookie
}

func (p *localCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.jar[u.Host] = cookies
}

func (p *localCookieJar) Cookies(u *url.URL) []*http.Cookie {
	return p.jar[u.Host]
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
