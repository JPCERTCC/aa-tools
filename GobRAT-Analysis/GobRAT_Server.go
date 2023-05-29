/* =========================================================
- GobRAT Analsys Tool
    Author: Yuma Masubuchi
    Version: 1.0
    Data: 20230522
    This tool has been tested in the following environments.
        - Linux debian 4.19.0-9-amd64
        - go version go1.20.2 linux/amd64
 ========================================================= */

package main

import (
    "bytes"
    "encoding/gob"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "os"
    "io"
    "strconv"
    "log"
    "net"
    "time"
    "crypto/tls"
    "bufio"
)

/* ======================== Config ======================== */
const (
    Conf_crtFilename = "server.crt"
    Conf_keyFilename = "server.key"
    Conf_maxBytes = 4096
    Conf_protocol = "tcp"
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



func handle(conn net.Conn) {
    timeoutDuration := Conf_waitTime * time.Second

    fmt.Println("[+] Launching server...")
    conn.SetReadDeadline(time.Now().Add(timeoutDuration))

    remoteAddr := conn.RemoteAddr().String()
    fmt.Println("[+] Client connected from " + remoteAddr)
    read(conn)

    for {
        switch (g_cmd - 2) {
        case 0:
            /* Supported */
            var m = map[string]string{"ip":"2.2.2.2", "local":"192.168.1.111,","flags":"L", "connected":"9",}
            g_package = PACKAGE{Type: g_cmd, ParamLength: uint16(len(m)),Param: m}
            resp(conn)
            read(conn)
            read(conn)

        case 1:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))
            g_package = PACKAGE{Type: g_cmd}
            resp(conn)
            read(conn)

        case 3:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))
            g_package = PACKAGE{Type: g_cmd}
            resp(conn)
            read(conn)
            read(conn)

        case 4:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))
            g_package = PACKAGE{Type: g_cmd}
            resp(conn)

        case 6:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))
            lscmd := "test connect"
            byteContent := []byte(lscmd)              
            g_package = PACKAGE{Type: g_cmd, Content: byteContent}
            resp(conn)
            read(conn)
            
        case 7:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))
            shellcmd := "ping 8.8.8.8"
            byteContent := []byte(shellcmd)              
            g_package = PACKAGE{Type: g_cmd, Content: byteContent}
            resp(conn)
            read(conn)

        case 8:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))

            lscmd := "ls -la"
            byteContent := []byte(lscmd)              
            g_package = PACKAGE{Type: g_cmd, Content: byteContent}
            resp(conn)
            read(conn)

        case 0xD:
            /* Semi Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))
            var mapParam = map[string]string{"filename":"/Mal/ls", "path":"/Mal/dummyfile2", "segment":"1"}

            g_package = PACKAGE{Type: g_cmd,ParamLength: uint16(len(mapParam)),Param: mapParam}
            resp(conn)
            read(conn)
            read(conn)

        case 0x10:
            /* Semi Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))
            var mapParam = map[string]string{"filename":"/Mal/ls", "path":"/Mal/dummyfile3", "segment":"1"}
            g_package = PACKAGE{Type: g_cmd,ParamLength: uint16(len(mapParam)),Param: mapParam}
            resp(conn)
            read(conn)
            read(conn)

        case 0x16:
            /* Supported */
            var m = map[string]string{"flags":"L", }
            g_package = PACKAGE{Type: g_cmd, BotCount: 4, ParamLength: uint16(len(m)),Param: m}

            fmt.Println("[+] cmd ", (g_cmd - 2))
            resp(conn)
            read(conn)

        case 0x17:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))

            type jsonTest struct {
                Testone map[string]string `json:"testone"`
            }
            ContentJson := jsonTest{
                Testone: map[string]string{"dest":"192.168.1.254", "port":"9999"},
            }
            jsonb, err := json.Marshal(ContentJson)
            if err != nil {
                fmt.Println("error:", err)
            }
            g_package = PACKAGE{Type: g_cmd, Content: jsonb}

            resp(conn)
            read(conn)
            connCmd0x17, errCmd0x17 := net.Dial("tcp", "192.168.1.11:9999")
            if errCmd0x17 != nil {
                log.Println(errCmd0x17)
                return
            }
            defer connCmd0x17.Close()

            g_cmd = 1 + 2
            g_package = PACKAGE{Type: g_cmd}    
            fmt.Println("[+] cmd on NewChanel ", (g_cmd - 2))
            resp(connCmd0x17)
            read(connCmd0x17)

        case 0x18:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))

            var mapParam = map[string]string{"port":"444", "password":"p@ss","cipher":"AEAD_CHACHA20_POLY1305","status":"1"}                
            jsonb, err := json.Marshal(mapParam)
            if err != nil {
                fmt.Println("error:", err)
            }
            g_package = PACKAGE{Type: g_cmd, Content: jsonb}

            resp(conn)
            read(conn)

        case 0x19:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))

            var mapParam = map[string]string{"port":"444","status":"1"}                
            jsonb, err := json.Marshal(mapParam)
            if err != nil {
                fmt.Println("error:", err)
            }
            g_package = PACKAGE{Type: g_cmd, Content: jsonb}

            resp(conn)
            read(conn)

        case 0x1A:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))
            type jsonTest struct {
                Testone map[string]string `json:"testone"`
            }
            ContentJson := jsonTest{
                Testone: map[string]string{"dest":"192.168.1.254", "port":"9998"},
            }
            jsonb, err := json.Marshal(ContentJson)
            if err != nil {
                fmt.Println("error:", err)
            }
            g_package = PACKAGE{Type: g_cmd, Content: jsonb}

            resp(conn)
            read(conn)
            connCmd0x17, errCmd0x17 := net.Dial("udp", "192.168.1.1:9998")
            if errCmd0x17 != nil {
                log.Println(errCmd0x17)
                return
            }
            defer connCmd0x17.Close()

            g_cmd = 1 + 2
            g_package = PACKAGE{Type: g_cmd}    
            fmt.Println("[+] cmd on NewChanel ", (g_cmd - 2))
            resp(connCmd0x17)
            read(connCmd0x17)

        case 0x1B:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))

            var m = map[string]string{"port":"555", "frpIpAndPort":"2.2.2.2","status":"1",}
            b, err := json.Marshal(m)
            if err != nil {
                fmt.Println("error:", err)
            }
            if (HexDebugMode) {
                dumpByteSlice(b)
            }
            g_package = PACKAGE{Type: g_cmd, Content: b} 
            
            resp(conn)
            read(conn)

        case 0x1F:
            /* Supported */
            fmt.Println("[+] cmd ", (g_cmd - 2))
            var m = map[string]string{"path":"/Mal/dummyfile"}
            g_package = PACKAGE{Type: g_cmd, BotCount: 4, ParamLength: uint16(len(m)),Param: m}
            resp(conn)
            read(conn)

        case 0x25:
            fmt.Println("[+] cmd ", (g_cmd - 2))

            var m = map[string]string{"now":"1", "check_port":"22","weak_pass_type":"1,2,3,4,5", "thread_number":"2",}

            b, err := json.Marshal(m)
            if err != nil {
                fmt.Println("error:", err)
            }
            if (HexDebugMode) {
                dumpByteSlice(b)
            }            
            g_package = PACKAGE{Type: g_cmd, BotCount: 4, ParamLength: uint16(len(m)),Param: m, Content: b}

            resp(conn)
            read(conn)
            read(conn)

        case 0x27:
            fmt.Println("[+] cmd ", (g_cmd - 2))

            var m = map[string]string{"now":"1",}
            g_package = PACKAGE{Type: g_cmd, BotCount: 4, ParamLength: uint16(len(m)),Param: m}

            resp(conn)
            read(conn)

        case 0x2A:
            fmt.Println("[+] cmd ", (g_cmd - 2))

            var m = map[string]string{"now":"1", "thread_number":"2", "check_port":"500"}

            //var slice_boomip interface{}
            slice_boomip := []string{"192.168.1.240", "192.168.1.241",}

            var json_pocstep = map[string]string{"key1":"1"}
            b_json_pocstep, err := json.Marshal(json_pocstep)
            if err != nil {
                fmt.Println("error:", err)
            }
            m2 := make(map[string]interface{})
            m2["boomIp"] = slice_boomip
            m2["pocStep"] = b_json_pocstep

            b, err := json.Marshal(m2)
            if err != nil {
                fmt.Println("error:", err)
            }
            if (HexDebugMode) {
                dumpByteSlice(b)
            }            
            g_package = PACKAGE{Type: g_cmd, BotCount: 4, ParamLength: uint16(len(m)),Param: m, Content: b}
            resp(conn)
            read(conn)

        case 0x2D:
            fmt.Println("[+] cmd ", (g_cmd - 2))
            var m = map[string]string{"now":"1", "thread_number":"2", "password_dict":"1", "check_port":"500"}

            slice_boomip := []string{"192.168.1.240", "192.168.1.241",}

            var json_pocstep = map[string]string{"key1":"1"}
            b_json_step, err := json.Marshal(json_pocstep)
            if err != nil {
                fmt.Println("error:", err)
            }
            m2 := make(map[string]interface{})
            m2["boomIp"] = slice_boomip
            m2["step"] = b_json_step

            b, err := json.Marshal(m2)
            if err != nil {
                fmt.Println("error:", err)
            }
            if (HexDebugMode) {
                dumpByteSlice(b)
            }            

            g_package = PACKAGE{Type: g_cmd, BotCount: 4, ParamLength: uint16(len(m)),Param: m, Content: b}
            resp(conn)
            read(conn)

        case 0x30:
            fmt.Println("[+] cmd ", (g_cmd - 2))
            m := []string{"aaa.com"}
            b, err := json.Marshal(m)
            if err != nil {
                fmt.Println("error:", err)
            }
            if (HexDebugMode) {
                dumpByteSlice(b)
            }            

            g_package = PACKAGE{Type: g_cmd, Content: b}
            resp(conn)
            read(conn)

        case 0x31:
            fmt.Println("[+] cmd ", (g_cmd - 2))

            var m = map[string]string{"now":"1",}
            g_package = PACKAGE{Type: g_cmd, BotCount: 4, ParamLength: uint16(len(m)),Param: m}

            resp(conn)
            read(conn)
        default:
            fmt.Println("default")
            continue
        }

        // Input command
        inputCmd := bufio.NewScanner(os.Stdin)
        fmt.Print("Bot CMD >> ")
        inputCmd.Scan()
        cmd := inputCmd.Text()
        intVar, err := strconv.Atoi(cmd)
        if err != nil {
            log.Println(err)
            return
        }
        g_cmd = uint8(intVar) + 2
        fmt.Printf("[+] CMD: 0x%x\n", g_cmd - 2)
    }
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


func read(conn net.Conn) {
    fmt.Println("[+] RECV:")
    // create a buffe
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


func resp(conn net.Conn) {
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


func Server_GobRat_onTLS() {

    log.SetFlags(log.Lshortfile)

    cer, err := tls.LoadX509KeyPair(Conf_crtFilename, Conf_keyFilename)
    if err != nil {
        log.Println(err)
        return
    }

    config := &tls.Config{Certificates: []tls.Certificate{cer}}
    ln, err := tls.Listen(Conf_protocol, Conf_port, config) 
    if err != nil {
        log.Println(err)
        return
    }
    defer ln.Close()

    for {
        conn, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        go handle(conn)
    }
}


func main() {
    var cmd int
    var err error

    if len(os.Args) > 1{
        args := os.Args
        cmd, err = strconv.Atoi(args[1])
        if err != nil {
            panic(err)
        }
        cmd_uint8 := uint8(cmd)
        g_cmd = cmd_uint8 + 2
    } else {
        inputCmd := bufio.NewScanner(os.Stdin)
        fmt.Print("Bot CMD >> ")
        inputCmd.Scan()
        cmd := inputCmd.Text()

        intVar, err := strconv.Atoi(cmd)
        if err != nil {
            log.Println(err)
            return
        }
        g_cmd = uint8(intVar) + 2
    }

    fmt.Printf("[*] Start C2 simulation! CMD: 0x%x\n", g_cmd - 2)

    Server_GobRat_onTLS()
}
