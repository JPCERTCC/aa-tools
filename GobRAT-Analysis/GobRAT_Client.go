/* =========================================================
- GobRAT Analsys Tool
    Author: Yuma Masubuchi
    Version: 1.0
    Data: 20230509
    This tool has been tested in the following environments.
        - Linux debian 4.19.0-9-amd64
        - go version go1.20.2 linux/amd64
 ========================================================= */

package main

import (
    "fmt"
    "log"
    "encoding/gob"
    "encoding/binary"
    "net"
    "bytes"
    "time"
    "crypto/tls"
    "io"
)

/* ======================== Config ======================== */
const (
    Conf_maxBytes = 2048
    Conf_protocol = "tcp"
    Conf_ip = "192.168.1.10"
    Conf_port = ":80"
    Conf_waitTime = 60 * 60
    HexDebugMode = true
)
/* ========================================================= */

/* ======================== GobRAT structure =============== */
type PACKAGE struct {
    Type uint8
    BotCount uint16
    BotList []string
    ParamLength uint16
    Param map[string]string
    Content []uint8
}
/* ========================================================= */

/* ======================== Global Variables =============== */
var g_cmd uint8
var g_package PACKAGE
/* ========================================================= */



func read(conn net.Conn) {
    fmt.Println("[+] RECV:")
    // create a temp buffer
    tmp := make([]byte, Conf_maxBytes)

    for {
        _, err := conn.Read(tmp)
        if logerr(err) {
            break
        }

        var resvSize = tmp[:4]
        var resvSizeInt = binary.BigEndian.Uint32(resvSize)
        fmt.Println("\tDATA SIZE: ",  resvSizeInt)

        trimed_tmp := tmp[4:resvSizeInt+4]
        tmpbuff := bytes.NewBuffer(trimed_tmp)

        // creates a decoder object
        tmpstruct := new(PACKAGE)
        gobobj := gob.NewDecoder(tmpbuff)
        
        // decodes buffer and unmarshals it into a Message struct
        gobobj.Decode(&tmpstruct)

        fmt.Println("\tPACKAGE")
        fmt.Println("\t\tType: ", tmpstruct.Type)
        fmt.Println("\t\tBotCount: ", tmpstruct.BotCount)
        fmt.Println("\t\tBotList: ", tmpstruct.BotList)
        fmt.Println("\t\tParamLength: ", tmpstruct.ParamLength)
        fmt.Println("\t\tParam: ", tmpstruct.Param)
        fmt.Println("\t\tContent: ", tmpstruct.Content)

        if (HexDebugMode) {
            dumpByteSlice(tmpstruct.Content)
        }
        return
    }
}

func send(conn net.Conn) {
    bin_buf := new(bytes.Buffer)

    // create a encoder object
    gobobje := gob.NewEncoder(bin_buf)
    // encode buffer and marshal it into a gob object
    gobobje.Encode(&g_package)

    dataSize := len(bin_buf.Bytes())	

    dataSizeB := i32tob_littleEndian(uint32(dataSize))

    bytesall := append(dataSizeB, bin_buf.Bytes()... )	

    fmt.Println("[+] SEND:")
    fmt.Println("\tDATA SIZE:", dataSize)
    fmt.Println("\tPACKAGE")
    fmt.Println("\t\tType: ", g_package.Type)
    fmt.Println("\t\tBotCount: ", g_package.BotCount)
    fmt.Println("\t\tBotList: ", g_package.BotList)
    fmt.Println("\t\tParamLength: ", g_package.ParamLength)
    fmt.Println("\t\tParam: ", g_package.Param)
    fmt.Println("\t\tContent: ", g_package.Content)
    
    if (HexDebugMode) {
        dumpByteSlice(bytesall)
    }
    conn.Write(bytesall)
}


func logerr(err error) bool {
    if err != nil {
        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            log.Println("read timeout:", err)
        } else if err == io.EOF {
        } else {
            log.Println("read error:", err)
        }
        return true
    }
    return false
}


func i32tob(val uint32) []byte{
    r := make([]byte, 4)
    for i := uint32(0); i < 4; i++ {
        r[i] = byte((val >> (8 * i)) & 0xff)
    }
    return r
}


func i32tob_littleEndian(val uint32) []byte{
    r := make([]byte, 4)
    for i := uint32(0); i < 4; i++ {
        r[3-i] = byte((val >> (8 * i)) & 0xff)
    }
    return r
}


func dumpByteSlice(b []byte) {
    var a [16]byte
    n := (len(b) + 15) &^ 15
    for i := 0; i < n; i++ {
        if i%16 == 0 {
            fmt.Printf("0x%03X", i)
        }
        if i%8 == 0 {
            fmt.Print(" ")
        }
        if i < len(b) {
            fmt.Printf(" %02X", b[i])
        } else {
            fmt.Print("   ")
        }
        if i >= len(b) {
            a[i%16] = ' '
        } else if b[i] < 32 || b[i] > 126 {
            a[i%16] = '.'
        } else {
            a[i%16] = b[i]
        }
        if i%16 == 15 {
            fmt.Printf("  %s\n", string(a[:]))
        }
    }
}


func main() {
    fmt.Println("[*] Start Client!");
    log.SetFlags(log.Lshortfile)

    conf := &tls.Config{
        InsecureSkipVerify: true,
    }
    conn, err := tls.Dial(Conf_protocol, Conf_ip + Conf_port, conf)
    if err != nil {
        log.Println(err)
        return
    }
    defer conn.Close()

    timeoutDuration := Conf_waitTime * time.Second
    conn.SetReadDeadline(time.Now().Add(timeoutDuration))

    g_cmd = 1
    var m = map[string]string{"mac":"000c29582213"}
    g_package = PACKAGE{Type: g_cmd, Param: m}

    send(conn)
    read(conn)
    read(conn)

    fmt.Println("[*] Done");
}
