package mgosec

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	mgo "gopkg.in/mgo.v2"
)

//AuthMechanism represents a MongoDB authentication mechanism
type AuthMechanism string

const (
	//ScramSha1 = SCRAM-SHA-1
	ScramSha1 AuthMechanism = "SCRAM-SHA-1"
	//MongoCR = MONGODB-CR
	MongoCR AuthMechanism = "MONGODB-CR"
	//PlainAuth = PLAIN
	PlainAuth AuthMechanism = "PLAIN"
	//X500 = MONGODB-X500
	X500 AuthMechanism = "MONGODB-X500"
	//GssAPI = GSSAPI
	GssAPI AuthMechanism = "GSSAPI"
	//None is used to show that authentication is disabled
	None AuthMechanism = ""
)

var authMechanisms = []AuthMechanism{ScramSha1, MongoCR, PlainAuth, X500, GssAPI, None}

//Dial dials a MongoDB server with the provided MongoDB connection string,
//as supplied to the mongo utility, an auth mechanism (see AuthMechanism),
//and a TLS configuration
func Dial(connString string, authMechanism AuthMechanism, conf *tls.Config) (*mgo.Session, error) {
	dialInfo, err := mgo.ParseURL(connString)
	if err != nil {
		return nil, err
	}

	dialInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
		return tls.Dial("tcp", addr.String(), conf)
	}
	dialInfo.Timeout = 5 * time.Second

	if authMechanism == None {
		dialInfo.Username = ""
		dialInfo.Password = ""
	}

	dialInfo.Mechanism = string(authMechanism)

	return mgo.DialWithInfo(dialInfo)
}

//DialInsecure dials a MongoDB server with the provided MongoDB connection string,
//as supplied to the mongo utility, an auth mechanism (see AuthMechanism).
//Note: this method does not encrypt any information placed on the wire,
//including authentication details
func DialInsecure(connString string, authMechanism AuthMechanism) (*mgo.Session, error) {
	dialInfo, err := mgo.ParseURL(connString)
	if err != nil {
		return nil, err
	}

	dialInfo.Timeout = 5 * time.Second

	if authMechanism == None {
		dialInfo.Username = ""
		dialInfo.Password = ""
	}

	dialInfo.Mechanism = string(authMechanism)

	return mgo.DialWithInfo(dialInfo)
}

//ParseAuthMechanism parses a string representation of a MongoDB
//authentication mechanism and returns the AuthMechanism which matches
func ParseAuthMechanism(mechanism string) (AuthMechanism, error) {
	mechanism = strings.ToUpper(mechanism)
	strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, mechanism)
	for _, authMechanism := range authMechanisms {
		if mechanism == string(authMechanism) {
			return authMechanism, nil
		}
	}
	return None, fmt.Errorf("%s did not match an existing MongoDB "+
		"authentication mechanism", mechanism)
}
