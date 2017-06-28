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

//MongoAuthMechanism represents a MongoDB authentication mechanism
type MongoAuthMechanism string

const (
	//ScramSha1 = SCRAM-SHA-1
	ScramSha1 MongoAuthMechanism = "SCRAM-SHA-1"
	//MongoCR = MONGODB-CR
	MongoCR MongoAuthMechanism = "MONGODB-CR"
	//PlainAuth = PLAIN
	PlainAuth MongoAuthMechanism = "PLAIN"
	//X500 = MONGODB-X500
	X500 MongoAuthMechanism = "MONGODB-X500"
	//GssAPI = GSSAPI
	GssAPI MongoAuthMechanism = "GSSAPI"
	//None is used to show that authentication is disabled
	None MongoAuthMechanism = ""
)

var authMechanisms = []MongoAuthMechanism{ScramSha1, MongoCR, PlainAuth, X500, GssAPI, None}

//Dial dials a MongoDB server with the provided MongoDB connection string,
//as supplied to the mongo utility, an auth mechanism (see MongoAuthMechanism),
//and a TLS configuration
func Dial(connString string, authMechanism MongoAuthMechanism, conf *tls.Config) (*mgo.Session, error) {
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

//ParseMongoAuthMechanism parses a string representation of a MongoDB
//authentication mechanism and returns the MongoAuthMechanism which matches
func ParseMongoAuthMechanism(mechanism string) (MongoAuthMechanism, error) {
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
