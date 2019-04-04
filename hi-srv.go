package main

import (
	"fmt"
	"log"
	"strconv"
  "net/http"
  "strings"
	"time"
	"net"

	"database/sql"
	_ "github.com/mattn/go-sqlite3"

	"github.com/miekg/dns"
)

var records = map[string]string{
	"test.service.": "192.168.0.2",
}
/*
dig -p 5353 @localhost google.com
*/

type RecentBlock struct {
	When time.Time
	Name string
	From net.Addr
	IpStr string
}

var recentBlockStart time.Time
var recentBlock, recentBlock2 []RecentBlock
var recentBlockDomain map[string]RecentBlock
func AddRecentBlock(name string, from net.Addr) {
	if recentBlockDomain == nil {
		recentBlockDomain = make(map[string]RecentBlock)
	}
	now := time.Now()
	if now.Sub(recentBlockStart) > 1 * time.Hour {
		recentBlockStart = now
		recentBlock2 = recentBlock
		recentBlock = make([]RecentBlock,0)
	}
	rb := NewRecentBlock(name, from)
	if _,ok := recentBlockDomain[name]; ok {
		// already there
		return
	}
	recentBlockDomain[name] = rb
	recentBlock = append(recentBlock, rb)
}

func NewRecentBlock(name string, from net.Addr) RecentBlock {
	out := RecentBlock{Name:name}
	out.From = from
	out.IpStr = ipAddrStr(from)
	out.When = time.Now()
	return out
}


func ipAddrStr(ipPort net.Addr) string {
	ipPortStr := ipPort.String()
	rIdx := strings.LastIndex(ipPortStr, ":")
	return ipPortStr[0:rIdx]
}

func secondLevel(nom0 string) string {
	nom := nom0
	nom = nom[:len(nom)-1]
	rIdx := strings.LastIndex(nom, ".")
	nom = nom[:rIdx]
	rIdx = strings.LastIndex(nom, ".")
	if rIdx < 0 {
		rIdx = 0
	} else {
		rIdx++
	}
	nom = nom0[rIdx:]
	log.Printf(" second %s %s", nom, nom0)
	return nom
}

func lookupWhite(nom0 string) bool {
	// TODO multiple queries and just 2nd level
	nom := secondLevel(nom0)

	rows,err:=db.Query("select ifnull(until,0) from dns_wl where domain=?",nom)
	if err != nil {
		log.Printf("lookupWhite err %s %s", nom, err.Error())
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var until int64
		err := rows.Scan(&until)
		if err != nil {
			log.Printf("lookupWhite rowE %s %s", nom, err.Error())
			continue
		}
		if until <= 0 || until > time.Now().Unix() {
			return true
		} else {
			return false
		}
	}	
	return false
}

func lookupDev(remoteIpPort net.Addr) bool {
	ipStr := ipAddrStr(remoteIpPort) 
	log.Printf("lookupDev %s %s", ipStr, remoteIpPort.String())
	rows,err:=db.Query("select ifnull(until,0) from dev_wl where ip=?",ipStr)
	if err != nil {
		log.Printf("lookupDev err %s %s", ipStr, err.Error())
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var until int64
		err := rows.Scan(&until)
		if err != nil {
			log.Printf("lookupDev rowE %s %s", ipStr, err.Error())
			continue
		}
		if until <= 0 || until > time.Now().Unix() {
			return true
		} else {
			return false
		}
	}	
	return false
}

func parseQuery(w dns.ResponseWriter, m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s\n", q.Name)
			ip := records[q.Name]
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else if lookupWhite(q.Name) || lookupDev(w.RemoteAddr()) {
				ipStr := "127.22.22.22"
				ips, err := net.LookupIP(q.Name) //[:len(q.Name)-1])
				if err != nil {
					log.Printf("lookupErr %s %s", q.Name, err.Error())
				} else {
					for _, ip := range ips {
						if ip.To4() == nil {
							continue
						}
						ipStr = ip.String()
						break
					}	
				}
				log.Printf("lookup %s %s", q.Name, ipStr)
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ipStr))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			} else {
				AddRecentBlock(q.Name, w.RemoteAddr())
				
				rr, err := dns.NewRR(fmt.Sprintf("%s A 44.55.66.104", q.Name))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(w, m)
		// log.Printf("opcode q from " + w.RemoteAddr().String())
	}

	w.WriteMsg(m)
}

var db *sql.DB
func main() {
	var err error
	db, err = sql.Open("sqlite3", "./dns-wl.db")
	if err != nil {
		log.Fatal(err)
		log.Printf("sqlite3 open dns-wl.db failed")
		return
	}
	/*
	create table dev_wl ( ip text, until integer, who text );
	create unique index ip_idx on dev_wl ( ip );
	insert into dev_wl ( ip ) values ( '127.0.0.1' );

	create table dns_wl ( domain text, until integer, who text );
	create unique index domain_idx on dns_wl ( domain );
	insert into dns_wl ( domain ) values ( 'google.com.' );

	create table users ( user text, password text );
	*/
	go mainWeb()
	mainDns()
}
func mainDns() {
	// attach request handler func
	dns.HandleFunc(".", handleDnsRequest)

	// start server
	port := 5353
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}

}




var cnt int

func sayHello(w http.ResponseWriter, r *http.Request) {
  var message string
  //message := r.URL.Path
  //message = strings.TrimPrefix(message, "/")

  w.Header().Add("Content-type", "text/html")
  //message = "Content-type: text/html\r\n\r\n"
  message = ""
  /*
  message += "Hello " + fmt.Sprintf(" %d <br>", cnt)
  for _,rb := range append(recentBlock, recentBlock2...) {
    message = message + rb.Name + " "+ rb.IpStr +" " + rb.When.String() +"<br>\n"
  }
  // */
  cnt++


  message += "<form action=unblock method=post>\n"
  seenIp := make(map[string]int)
  for _,rb := range append(recentBlock, recentBlock2...) {
    message += rb.Name 
    // TODO second level
    message += " unblock for <input type=text name=dn_"+rb.Name+" value=0.0> days"
    message += "<br>\n"
  }
  for _,rb := range append(recentBlock, recentBlock2...) {
    if _, ok := seenIp[rb.IpStr]; ok {
      continue
    }
    message += rb.IpStr + " unblock for <input type=text name=ip_"+rb.IpStr+" value=0.0> days<br>\n"
    seenIp[rb.IpStr] = 1
  }
  message += "user:<input type=text name=user><br>\n"
  message += "password:<input type=password name=password><br>\n"
  message += "<input type=submit>\n"
  message += "</form>\n"

  w.Write([]byte(message))
  fmt.Println("did serv " + fmt.Sprintf("%d",cnt))
}
func unblockForm(w http.ResponseWriter, r *http.Request) {
  r.ParseForm()
  w.Header().Add("Content-type", "text/html")
  message := ""
  message += "a" + r.PostFormValue("noSuch") + "b<br>\n"
  user := r.PostFormValue("user")
  if !lookupUser(user, r.PostFormValue("password")) {
     message += "bad user/password"
     w.Write([]byte(message))
     return
  }

  for _,rb := range append(recentBlock, recentBlock2...) {
    f := 0.0
    f, _ = strconv.ParseFloat(r.PostFormValue("ip_"+rb.IpStr), 32)
    if f == 0.0 {
      continue
    }
    var until int64
    until = int64(time.Now().Unix() + int64(f * 3600.0 * 24.0))
    _,err := db.Exec("insert into dev_wl(ip,who,until)values(?,?,?)",rb.IpStr,user,until)
    if err != nil {
      fmt.Println("unb ip %s",err.Error())
    }
    fmt.Println("did unblock %s %d ip",rb.IpStr, until)
  }
  for _,rb := range append(recentBlock, recentBlock2...) {
    f := 0.0
    f, _ = strconv.ParseFloat(r.PostFormValue("dn_"+rb.Name), 32)
    if f == 0.0 {
      continue
    }
    nom := secondLevel(rb.Name)
    var until int64
    until = int64(time.Now().Unix() + int64(f * 3600.0 * 24.0))
    _,err :=db.Exec("insert into dns_wl(domain,who,until)values(?,?,?)",nom,user,until)
    if err != nil {
      fmt.Println("unb dns %s",err.Error())
    }
    fmt.Println("did unblock %s %d nom",nom, until)
  }

  fmt.Println("did unblock")
  w.Write([]byte(message))
}
func lookupUser(user string, password string) bool {
	rows,err:=db.Query("select count(*) from users where user=? and password=?",user, password)
	if err != nil {
		log.Printf("lookupU err %s %s", user, err.Error())
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var rcnt int
		rows.Scan(&rcnt)
		return rcnt > 0
	}	
	return false
}

func mainWeb() {
  cnt = 0
  fmt.Println("starting")
  http.HandleFunc("/", sayHello)
  http.HandleFunc("/unblock", unblockForm)
  if err := http.ListenAndServe(":8080", nil); err != nil {
    panic(err)
  }
}
