//go:build cfgmgr
// +build cfgmgr

package factory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/coreswitch/cmd"
	rpc "github.com/coreswitch/openconfigd/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
)

const (
	cfgServerURL         = ":2650"
	cfgConnRetryInterval = 5
)

var (
	lis net.Listener
	ch  chan interface{}
)

// Register amf with cli port 2701
func registerModule(client rpc.RegisterClient) error {
	req := &rpc.RegisterModuleRequest{
		Module: "amf",
		Host:   "",
		Port:   "2701",
	}
	_, err := client.DoRegisterModule(context.Background(), req)
	if err != nil {
		return err
	}
	return nil
}

// cli definition by JSON format.
const cliSpec = `
[
    {
        "name": "show_amf_session",
        "line": "show amf session",
        "mode": "exec",
        "helps": [
            "Show running system information",
            "AMF information",
            "AMF sessions"
        ]
    },
    {
        "name": "show_amf_status",
        "line": "show amf status",
        "mode": "exec",
        "helps": [
            "Show running system information",
            "AMF information",
            "AMF status"
        ]
    }
]
`

var cliMap = map[string]func(*cliTask, []interface{}){
	"show_amf_status":  showAMFStatus,
	"show_amf_session": showAMFSession,
}

type cliTask struct {
	Json     bool
	First    bool
	Continue bool
	Str      string
	Index    interface{}
}

func showAMFStatus(t *cliTask, Args []interface{}) {
	t.Str = "show amf status output"
}

func showAMFSession(t *cliTask, Args []interface{}) {
	t.Str = "show amf session output"
}

var cliParser *cmd.Node

func registerCli(client rpc.RegisterClient) {
	var clis []rpc.RegisterRequest
	json.Unmarshal([]byte(cliSpec), &clis)

	cliParser = cmd.NewParser()

	for _, cli := range clis {
		cli.Module = "amf"
		cli.Privilege = 1
		cli.Code = rpc.ExecCode_REDIRECT_SHOW

		_, err := client.DoRegister(context.Background(), &cli)
		if err != nil {
			grpclog.Fatalf("client DoRegister failed: %v", err)
		}
		cliParser.InstallLine(cli.Line, cliMap[cli.Name])
	}
}

func commandHandler(command int, path []string) {
	if command == cmd.Set {
		fmt.Println("[cmd] add", path)
	} else {
		fmt.Println("[cmd] del", path)
	}
	ret, fn, args, _ := parser.ParseCmd(path)
	if ret == cmd.ParseSuccess {
		fn.(func(int, cmd.Args) int)(command, args)
		validate()
	}
}

func registerCommand(client rpc.ConfigClient) {
	commandInit()

	stream, err := client.DoConfig(context.Background())
	if err != nil {
		grpclog.Fatalf("client DoConfig failed: %v", err)
	}
	subscription := []*rpc.SubscribeRequest{
		{rpc.SubscribeType_COMMAND, "amf"},
		{rpc.SubscribeType_COMMAND, "nrf-uri"},
	}
	msg := &rpc.ConfigRequest{
		Type:      rpc.ConfigType_SUBSCRIBE_REQUEST,
		Module:    "AMF",
		Port:      2701,
		Subscribe: subscription,
	}
	err = stream.Send(msg)
	if err != nil {
		grpclog.Fatalf("client DoConfig subscribe failed: %v", err)
	}

loop:
	for {
		conf, err := stream.Recv()
		if err == io.EOF {
			break loop
		}
		if err != nil {
			break loop
		}
		switch conf.Type {
		case rpc.ConfigType_COMMIT_START:
			fmt.Println("[cmd] Commit Start")
		case rpc.ConfigType_COMMIT_END:
			fmt.Println("[cmd] Commit End")
			commandSync()
			msg := &rpc.ConfigRequest{
				Type: rpc.ConfigType_API_CALL_FINISHED,
			}
			err = stream.Send(msg)
			if err != nil {
				grpclog.Fatalf("gRPC stream send error: %v", err)
				return
			}
			if cfgSyncCh != nil {
				close(cfgSyncCh)
				cfgSyncCh = nil
			}
		case rpc.ConfigType_SET, rpc.ConfigType_DELETE:
			commandHandler(int(conf.Type), conf.Path)
		default:
		}
	}
}

// Register module and API to openconfigd.
func register() {
	ch = make(chan interface{})
	for {
		conn, err := grpc.Dial(cfgServerURL,
			grpc.WithInsecure(),
			grpc.FailOnNonTempDialError(true),
			grpc.WithBlock(),
			grpc.WithTimeout(time.Second*cfgConnRetryInterval),
		)
		if err == nil {
			registerModule(rpc.NewRegisterClient(conn))
			registerCli(rpc.NewRegisterClient(conn))
			registerCommand(rpc.NewConfigClient(conn))
			for {
				<-ch
				break
			}
			conn.Close()
		} else {
			interval := rand.Intn(cfgConnRetryInterval) + 1
			select {
			// Wait timeout.
			case <-time.After(time.Second * time.Duration(interval)):
			}
		}
	}
}

func (s *execServer) DoExec(_ context.Context, req *rpc.ExecRequest) (*rpc.ExecReply, error) {
	reply := new(rpc.ExecReply)

	// Fill in this when dynamic completion is needed.
	if req.Type == rpc.ExecType_COMPLETE_DYNAMIC {
	}

	return reply, nil
}

type execModuleServer struct{}

func newExecModuleServer() *execModuleServer {
	return &execModuleServer{}
}

func (s *execModuleServer) DoExecModule(_ context.Context, req *rpc.ExecModuleRequest) (*rpc.ExecModuleReply, error) {
	reply := new(rpc.ExecModuleReply)
	return reply, nil
}

type execServer struct{}

func newExecServer() *execServer {
	return &execServer{}
}

type cliServer struct {
}

func newCliServer() *cliServer {
	return &cliServer{}
}

func newCliTask() *cliTask {
	return &cliTask{
		First: true,
	}
}

// Show is callback function invoked by gRPC event from openconfigd.
func (s *cliServer) Show(req *rpc.ShowRequest, stream rpc.Show_ShowServer) error {
	reply := &rpc.ShowReply{}

	result, fn, args, _ := cliParser.ParseLine(req.Line)
	if result != cmd.ParseSuccess || fn == nil {
		reply.Str = "% Command can't find: \"" + req.Line + "\"\n"
		err := stream.Send(reply)
		if err != nil {
			fmt.Println(err)
		}
		return nil
	}

	show := fn.(func(*cliTask, []interface{}))
	task := newCliTask()
	task.Json = req.Json
	for {
		task.Str = ""
		task.Continue = false
		show(task, args)
		task.First = false

		reply.Str = task.Str
		err := stream.Send(reply)
		if err != nil {
			fmt.Println(err)
			break
		}
		if !task.Continue {
			break
		}
	}
	return nil
}

func cliServe(grpcEndpoint string) error {
	lis, err := net.Listen("tcp", grpcEndpoint)
	if err != nil {
		return err
	}

	grpcServer := grpc.NewServer()
	rpc.RegisterExecServer(grpcServer, newExecServer())
	rpc.RegisterExecModuleServer(grpcServer, newExecModuleServer())
	rpc.RegisterShowServer(grpcServer, newCliServer())

	grpcServer.Serve(lis)
	return nil
}

// CfgMgr starts management services.
func CfgMgrStart() {
	go cliServe(":2701")
	go register()
}

// CfgMgrStop stops management services.
func CfgMgrStop() {
	lis.Close()
	close(ch)
}
