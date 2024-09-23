package main

import "path/filepath"
import "encoding/xml"
import "os"
import "encoding/csv"
import "strings"
import "io/ioutil"
import "fmt"
import "errors"

type Nmaprun struct {
	Scanner          string `xml:"scanner,attr"`
	Args             string `xml:"args,attr"`
	Start            string `xml:"start,attr"`
	Startstr         string `xml:"startstr,attr"`
	Version          string `xml:"version,attr"`
	XmlOutputVersion string `xml:"xmloutputversion,attr"`

	Scaninfo  Scaninfo   `xml:"scaninfo"`
	Verbose   Verbose    `xml:"verbose"`
	Debugging Debugging  `xml:"debugging"`
	Hosts     []Host     `xml:"host"`
	Runstats  []Runstats `xml:"runstats"`
}

type Runstats struct {
	Finished Finished `xml:"finished"`
	Hosts    Hosts    `xml:"hosts"`
}
type Finished struct {
	Time    string `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Elapsed string `xml:"elapsed,attr"`
	Summary string `xml:"summary,attr"`
	Exit    string `xml:"exit,attr"`
}

type Hosts struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

type Scaninfo struct {
	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	Numservices int    `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

type Verbose struct {
	Level string `xml:"level,attr"`
}

type Debugging struct {
	Level string `xml:"level,attr"`
}

type Host struct {
	Starttime     string        `xml:"starttime,attr"`
	Endtime       string        `xml:"endtime,attr"`
	Address       Address       `xml:"address"`
	Hostnames     Hostnames     `xml:"hostnames"`
	Ports         Ports         `xml:"ports"`
	Os            Os            `xml:"os"`
	Uptime        Uptime        `xml:"uptime"`
	Distance      Distance      `xml:"distance"`
	TcpSequence   TcpSequence   `xml:"tcpsequence"`
	IpIdSequence  IpIdSequence  `xml:"ipidsequence"`
	TcpTsSequence TcpTsSequence `xml:"tcptssequence"`
	Trace         Trace         `xml:"trace"`
	Times         Times         `xml:"times"`
}
type Uptime struct {
	Seconds  int    `xml:"seconds,attr"`
	Lastboot string `xml:"lastboot,attr"`
}

type Distance struct {
	Value string `xml:",chardata"`
}
type TcpSequence struct {
	Index      string `xml:"index,attr"`
	Difficulty string `xml:"difficulty,attr"`
	Values     string `xml:values,attr"`
}
type IpIdSequence struct {
	Class  string `xml:"class,attr"`
	Values string `xml:"values,attr"`
}
type TcpTsSequence struct {
	Class  string `xml:"class,attr"`
	Values string `xml:"values,attr"`
}
type Trace struct {
	Hops []Hop `xml:"hop"`
}

type Hop struct {
	Ttl    string `xml:"ttl,attr"`
	IpAddr string `xml:"ipaddr,attr"`
	Rtt    string `xml:"rtt,attr"`
	Host   string `xml:"host,attr"`
}
type Times struct {
	Srtt   string `xml:"srtt,attr"`
	Rttvar string `xml:"rttvar,attr"`
	To     string `xml:"to"`
}

type Os struct {
	PortsUsed []PortsUsed `xml:"portused"`
	Osclass   []Osclass   `xml:"osclass"`
	Cpe       []Cpe       `xml:"cpe"`
	Osmatch   string      `xml:"osmatch"`
}

type PortsUsed struct {
	State  string `xml:"state,attr"`
	Proto  string `xml:"proto,attr"`
	PortId string `xml:"portid,attr"`
}

type Osclass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	OsFamily string `xml:"osfamily,attr"`
	Osgen    string `xml:"osgen,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

type Osmatch struct {
	Name     string `xml:"Name"`
	Accuracy int    `xml:"accuracy"`
	Line     int    `xml:"line"`
}

type Hostnames struct {
	Hostnames []Hostname `xml:"hostname"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type Address struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type Ports struct {
	ExtraPorts []ExtraPorts `xml:"extraports"`
	Ports      []Port       `xml:"port"`
}

type ExtraPorts struct {
	State        string         `xml:"state,attr"`
	Count        int            `xml:"count,attr"`
	ExtraReasons []ExtraReasons `xml:"extraports"`
}

type ExtraReasons struct {
	Reason string `xml:"reason,attr"`
	Count  int    `xml:"count,attr"`
}

type Port struct {
	Protocol string   `xml:"protocol,attr"`
	PortId   string   `xml:"portid,attr"`
	State    State    `xml:"state"`
	Service  Service  `xml:"service"`
	Cpe      []Cpe    `xml:"cpe"`
	Script   []Script `xml:"script"`
}

type Cpe struct {
	Value string `xml:",chardata"`
}

type State struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

type Service struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	OSType    string `xml:"ostype,attr"`
	Method    string `xml:"method,attr"`
	Conf      string `xml:"conf,attr"`
}

type Script struct {
	Id     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type CSVRow struct {
	Ip           string
	Hostname     string
	Port         string
	Service      string
	Confidence   string
	ScriptId     string
	ScriptOutput string
}

func trim(str string) string {

	str = strings.TrimSpace(str)
	str = strings.ReplaceAll(str, "\n", " ")
	str = strings.ReplaceAll(str, "\t", " ")
	str = strings.ReplaceAll(str, "\r", " ")

	return str
}

func ExtractNmap(run *Nmaprun, scan string) {

	rows := [][]string{{"Scan", "IP", "Hostname", "Port", "Service", "Confidence", "Script", "ScriptOutput"}}
	for _, host := range run.Hosts {

		hostname := ""
		if len(host.Hostnames.Hostnames) > 0 {
			hostname = host.Hostnames.Hostnames[0].Name
		}

		for _, port := range host.Ports.Ports {
			//script for port exists?
			if len(port.Script) > 0 {
				//output multiple rows per script
				for _, script := range port.Script {
					rows = append(rows, []string{scan, host.Address.Addr, hostname, port.PortId, port.Service.Name, port.Service.Conf, script.Id,
						trim(script.Output)})
				}
			} else {
				rows = append(rows, []string{scan, host.Address.Addr, hostname, port.PortId, port.Service.Name, port.Service.Conf, "", ""})
			}
		}
	}
	fileExists, err := os.OpenFile(os.Args[2], os.O_RDONLY, 0644)
	if !errors.Is(err, os.ErrNotExist) {
		fmt.Println("output file exists, appending...")
		rows = append(rows[:0], rows[0+1:]...)

	}
	defer fileExists.Close()

	f, _ := os.OpenFile(os.Args[2], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	w := csv.NewWriter(f)
	w.WriteAll(rows)

}

func main() {

	if len(os.Args) < 3 || len(os.Args)<1 {
		fmt.Println("usage: <nmap xml log> <output csv>\n./nmapXml2csv scan.xml scan.csv")
		os.Exit(1)
	}

	xmlFile, _ := os.Open(os.Args[1])
	xmlBytes, _ := ioutil.ReadAll(xmlFile)
	scan := Nmaprun{}
	xml.Unmarshal(xmlBytes, &scan)
	path := filepath.Base(os.Args[1])
	name := strings.TrimSuffix(path, filepath.Ext(os.Args[1]))

	ExtractNmap(&scan, name)
}
