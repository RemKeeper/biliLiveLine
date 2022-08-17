package main

import (
	"encoding/json"
	"fmt"
	"github.com/duanhunyiye/keyboard/listener/win32"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

type 配置文件 struct {
	RoomId     string
	Ps         string
	PrintColor int
	PS         string
	LineKey    string
	PPs        string
}
type 队列 struct {
	Line []string
}

type Room struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Message string `json:"message"`
	Data    struct {
		RoomID     int   `json:"room_id"`
		ShortID    int   `json:"short_id"`
		UID        int   `json:"uid"`
		IsHidden   bool  `json:"is_hidden"`
		IsLocked   bool  `json:"is_locked"`
		IsPortrait bool  `json:"is_portrait"`
		LiveStatus int   `json:"live_status"`
		Encrypted  bool  `json:"encrypted"`
		LiveTime   int64 `json:"live_time"`
	} `json:"data"`
}

type Barrage struct {
	Code int `json:"code"`
	Data struct {
		Admin []struct {
			Text      string        `json:"text"`
			Nickname  string        `json:"nickname"`
			Medal     []interface{} `json:"medal"`
			CheckInfo struct {
				Ct string `json:"ct"`
			} `json:"check_info"`
		} `json:"admin"`
		Room []struct {
			Text       string        `json:"text"`
			Nickname   string        `json:"nickname"`
			UnameColor string        `json:"uname_color"`
			Medal      []interface{} `json:"medal"`
			CheckInfo  struct {
				Ct string `json:"ct"`
			} `json:"check_info"`
		} `json:"room"`
		Message string `json:"message"`
		Msg     string `json:"msg"`
	} `json:"data"`
}

var keyMap = map[win32.DWORD]string{
	8: "Backspace", 9: "Tab", 13: "Enter", 20: "CapsLock", 27: "Esc",

	32: "Space", 33: "PageUp", 34: "PageDown", 35: "End", 36: "Home", 37: "Left", 38: "Up", 39: "Right",
	40: "Down", 45: "Insert", 46: "Delete",

	48: "0", 49: "1", 50: "2", 51: "3", 52: "4", 53: "5", 54: "6", 55: "7", 56: "8", 57: "9",

	65: "a", 66: "b", 67: "c", 68: "d", 69: "e", 70: "f", 71: "g", 72: "h", 73: "i", 74: "j",
	75: "k", 76: "l", 77: "m", 78: "n", 79: "o", 80: "p", 81: "q", 82: "r", 83: "s", 84: "t",
	85: "u", 86: "v", 87: "w", 88: "x", 89: "y", 90: "z",

	91: "Win(left)", 92: "Win(right)",
	96: "0", 97: "1", 98: "2", 99: "3", 100: "4", 101: "5", 102: "6", 103: "7", 104: "8", 105: "9",
	106: "*", 107: "+", 109: "-", 110: ".", 111: "/",

	112: "F1", 113: "F2", 114: "F3", 115: "F4", 116: "F5", 117: "F6", 118: "F7", 119: "F8",
	120: "F9", 121: "F10", 122: "F11", 123: "F12",

	144: "NumLock", 160: "Shift(left)", 161: "Shift(right)", 162: "Ctrl(right)", 163: "Ctrl(left)",
	164: "Alt(left)", 165: "Alt(right)",

	186: ";", 187: "=", 188: ",", 189: "-", 190: ".", 191: "/", 192: "`",
	219: "[", 220: "\\", 221: "]", 222: "'",
}
var kbHook win32.HHOOK

type KBEvent struct {
	VkCode      win32.DWORD
	ProcessId   uint32
	ProcessName string
	WindowText  string
	Time        time.Time
}

var (
	windowText    string
	processId     uint32
	processName   string
	kbEventChanel = make(chan KBEvent, 200)
)
var lineup []string
var AllPrintColor int

func main() {
	var SelectLine int
	KeyBordString := make(chan string, 1)

	RoomId, PrintColor, Linekey := GetConfig()
	AllPrintColor = PrintColor
	var UserSelect = 0

	if len(RoomId) < 1 || PrintColor < 1 || len(Linekey) < 1 {
		RoomId = "2233"
		PrintColor = 4

		fmt.Println("请输入bilibili房间号并回车")
		fmt.Scanln(&RoomId)
		if RoomId == "11365" {
			fmt.Println("拒绝服务")
			os.Exit(444)
		}
		fmt.Println("排队关键词，默认为”排队“，不使用自定义请直接回车，多个关键词请使用任意符号分隔")
		fmt.Scanln(&Linekey)
		if len(Linekey) == 0 {
			Linekey = "排队"
		}
		fmt.Println("自定义颜色编号")
		for i := 1; i < 7; i++ {
			ColorPrint("这是测试字符", i)
			fmt.Print("编号" + strconv.Itoa(i) + "  ")
		}
		for i := 9; i < 15; i++ {
			ColorPrint("这是测试字符", i)
			fmt.Print("编号" + strconv.Itoa(i) + "  ")
		}
		fmt.Println()
		fmt.Scanln(&PrintColor)

		if SetConfig(RoomId, PrintColor, Linekey) {
			fmt.Println("配置信息已保存，下次启动将自动读取")
		} else {
			fmt.Println("配置文件保存失败")
		}
	}

	kbHook, err := win32.SetWindowsHookEx(win32.WH_KEYBOARD_LL, keyboardCallBack, 0, 0)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("已设置键盘Hook")
	}
	defer func(hhk win32.HHOOK) {
		_, err := win32.UnhookWindowsHookEx(hhk)
		if err != nil {

		}
	}(kbHook)

	go func() {
		RoomUrl := "https://api.live.bilibili.com/room/v1/Room/room_init?id=" + RoomId
		RealRoomId, err := http.Get(RoomUrl)
		if err != nil {
			fmt.Println("请求房间号错误，请检查您的网络环境", err.Error())
		} else {
			IdBody, _ := ioutil.ReadAll(RealRoomId.Body)
			err := RealRoomId.Body.Close()
			if err != nil {
				return
			}
			var RoomConfig Room
			json.Unmarshal(IdBody, &RoomConfig)
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {

				}
			}(RealRoomId.Body)
			switch {
			case RoomConfig.Code != 0:
				fmt.Println("房间号错误", RoomConfig.Msg, RoomConfig.Message)
				os.Exit(0)
			case RoomConfig.Data.IsHidden != false:
				fmt.Println("隐藏的房间")
				os.Exit(0)
			case RoomConfig.Data.IsLocked != false:
				fmt.Println("被封禁或锁定的房间")
				os.Exit(0)
			case RoomConfig.Data.IsPortrait != false || RoomConfig.Data.Encrypted != false:
				fmt.Println("未知的房间状态，输入1尝试解析弹幕（默认不解析）")
				fmt.Scanln(&UserSelect)
				if UserSelect != 1 {
					os.Exit(0)
				} else {
					break
				}
			default:

				fmt.Println("房间真实ID为", RoomConfig.Data.RoomID)
				fmt.Println("用户uid为", RoomConfig.Data.UID)
				if RoomConfig.Data.LiveStatus == 1 {
					fmt.Println("用户直播状态:直播中")
					fmt.Println("开播时间", time.Unix(RoomConfig.Data.LiveTime, 0))
					fmt.Println("已直播", time.Now().Sub(time.Unix(RoomConfig.Data.LiveTime, 0)))
				} else {
					fmt.Println("用户直播状态:未直播")
				}

				fmt.Println("基础状态检查完成，开始解析弹幕")
				LineTemp := GetLine()
				if len(LineTemp) != 0 {
					lineSelect := ""
					fmt.Println("检测到上一次队列缓存，直接回车启用，不启用请输入”D“并回车")
					fmt.Scanln(&lineSelect)
					if lineSelect == "D" || lineSelect == "d" {
						err := os.Rename("./line.json", "lineback.json")
						if err != nil {
							fmt.Println(err.Error())
						}
						fmt.Println("已删除上次队列，即将开始弹幕解析")
						time.Sleep(time.Second * 2)
						CallClear()
					} else {
						lineup = LineTemp
						CallClear()
						for _, s := range lineup {
							ColorPrint(s, PrintColor)
							fmt.Println()
						}
					}
				}
				BarrageTick := time.Tick(time.Second)
				var LastAdBaeeageCt map[int]string
				LastAdBaeeageCt = make(map[int]string)

				RoomLink := "https://api.live.bilibili.com/xlive/web-room/v1/dM/gethistory?roomid=" + strconv.Itoa(RoomConfig.Data.RoomID)
				for i := 0; i < 9; i++ {
					LastAdBaeeageCt[i] = ""
				}
				var LAdkey = 0
				for {
					<-BarrageTick
					BarrageXhr, err := http.Get(RoomLink)
					if err != nil {
						fmt.Println("弹幕解析错误，请检查网络环境", err.Error())
						os.Exit(2)
					}
					BarrageJson, _ := ioutil.ReadAll(BarrageXhr.Body)
					var BaeeageJson Barrage
					UJsonerr := json.Unmarshal(BarrageJson, &BaeeageJson)
					if UJsonerr != nil {
						return
					}
					BodyCloseErr := BarrageXhr.Body.Close()
					if BodyCloseErr != nil {
						return
					}

					for Adkey, Advalue := range BaeeageJson.Data.Room {
						if Advalue.CheckInfo.Ct == LastAdBaeeageCt[9] {
							LAdkey = Adkey
						}
						LastAdBaeeageCt[Adkey] = Advalue.CheckInfo.Ct
					}
					for i := LAdkey + 1; i <= len(BaeeageJson.Data.Room)-1; i++ {
						if LAdkey < 9 {
							if strings.Contains(Linekey, BaeeageJson.Data.Room[i].Text) {
								lineup = append(lineup, BaeeageJson.Data.Room[i].Nickname)
								lineup = removeRepeatElement(lineup)
								SetLine(lineup)
								PrintLine(lineup, PrintColor, -1)
							}
						}
					}
				}
			}
		}
	}()
	go fakekeydump(KeyBordString)
	go func() {
		for {
			data, _ := <-KeyBordString
			lineLength := len(lineup)
			switch {
			case data == "Down" || data == "Right":
				SelectLine++
				if SelectLine > lineLength-1 {
					SelectLine = 0
				}
				PrintLine(lineup, PrintColor, SelectLine)
			case data == "Up" || data == "Left":
				SelectLine--
				if SelectLine < 0 {
					SelectLine = lineLength - 1
				}
				PrintLine(lineup, PrintColor, SelectLine)
			case data == "Delete":
				if !(SelectLine < 0 || SelectLine > lineLength-1) {
					lineup = append(lineup[:SelectLine], lineup[SelectLine+1:]...)
					SetLine(lineup)
					PrintLine(lineup, PrintColor, SelectLine)
				}
			case data == "End":
				SelectLine = -1
				PrintLine(lineup, PrintColor, SelectLine)
			}
		}
	}()
	go WebServerTwo()
	win32.GetMessage(new(win32.MSG), 0, 0, 0)

}

func ColorPrint(s string, i int) { //设置终端字体颜色
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("SetConsoleTextAttribute")
	handle, _, _ := proc.Call(uintptr(syscall.Stdout), uintptr(i))
	fmt.Print(s)
	handle, _, _ = proc.Call(uintptr(syscall.Stdout), uintptr(7))
	CloseHandle := kernel32.NewProc("CloseHandle")
	_, _, err := CloseHandle.Call(handle)
	if err != nil {
		return
	}
}

func PrintLine(lineup []string, PrintColor int, SelectLine int) {
	CallClear()
	for k, s := range lineup {
		if k == SelectLine {
			ColorPrint(s, PrintColor+1)
		} else {
			ColorPrint(s, PrintColor)
		}
		fmt.Println()
	}
}

func removeRepeatElement(list []string) []string {
	// 创建一个临时map用来存储数组元素
	temp := make(map[string]bool)
	index := 0
	for _, v := range list {
		// 遍历数组元素，判断此元素是否已经存在map中
		_, ok := temp[v]
		if ok {
			list = append(list[:index], list[index+1:]...)
		} else {
			temp[v] = true
		}
		index++
	}
	return list
}

var clear map[string]func() //create a map for storing clear funcs
func init() {
	clear = make(map[string]func()) //Initialize it
	clear["linux"] = func() {
		cmd := exec.Command("clear") //Linux example, its tested
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		if err != nil {
			return
		}
	}
	clear["windows"] = func() {
		cmd := exec.Command("cmd", "/c", "cls") //Windows example, its tested
		cmd.Stdout = os.Stdout
		err := cmd.Run()
		if err != nil {
			return
		}
	}
}
func CallClear() {
	value, ok := clear[runtime.GOOS] //runtime.GOOS -> linux, windows, darwin etc.
	if ok {                          //if we defined a clear func for that platform:
		value() //we execute it
	} else { //unsupported platform
		panic("Your platform is unsupported! I can't clear terminal screen :(")
	}
}

func SetConfig(roomid string, printColor int, linekey string) bool {
	ConfigJsonType := 配置文件{
		RoomId:     roomid,
		Ps:         "上面这个是房间号，修改请严格按照格式填写",
		PrintColor: printColor,
		PS:         "上面这个是打印颜色，数值请根据程序内显示数值填写",
		LineKey:    linekey,
		PPs:        "上面为队列触发关键词，多个关键词请用任意符号隔开",
	}
	ConfigJson, _ := json.MarshalIndent(ConfigJsonType, "", " ")
	fmt.Println(string(ConfigJson))
	lineupConfig := "./lineupConfig.json"
	_, ReadConfigErr := os.Open(lineupConfig)
	if ReadConfigErr != nil {
		fmt.Println("配置文件不存在，尝试创建")
		_, ConfigErr := os.Create(lineupConfig)
		if ConfigErr != nil {
			fmt.Println("配置文件创建失败", ConfigErr.Error())
			return false
		} else {
			err := ioutil.WriteFile(lineupConfig, ConfigJson, 0666)
			if err != nil {
				fmt.Println("配置文件更新失败", err.Error())
				return false
			} else {
				return true
			}
		}
	}
	return false
}
func GetConfig() (Roomid string, PrintColor int, Linekey string) {
	lineupConfigFile := "./lineupConfig.json"
	Configinfo, OpenErr := os.Open(lineupConfigFile)
	if OpenErr != nil {
		fmt.Println("配置读取错误", OpenErr)
		return
	} else {
		ReadByte := make([]byte, 1024)
		for {
			over, ReadByteErr := Configinfo.Read(ReadByte)
			if over == 0 || ReadByteErr == io.EOF {
				break
			}
			var ConfigSetGet 配置文件
			err := json.Unmarshal(ReadByte[:over], &ConfigSetGet)
			if err != nil {
				return
			}
			return ConfigSetGet.RoomId, ConfigSetGet.PrintColor, ConfigSetGet.LineKey
		}
	}
	return "", 0, ""
}

func SetLine(lp []string) {
	lineInfo := 队列{Line: lp}
	lineJson, _ := json.MarshalIndent(lineInfo, "", " ")
	lineConfigFile := "./line.json"
	WriteErr := ioutil.WriteFile(lineConfigFile, lineJson, 0666)
	if WriteErr != nil {
		fmt.Println("队列文件更新失败")
	}
}

func GetLine() []string {
	lineConfigFile := "./line.json"
	lineInfo, OpenErr := os.Open(lineConfigFile)
	defer func(lineInfo *os.File) {
		err := lineInfo.Close()
		if err != nil {
			panic(err)
		}
	}(lineInfo)
	if OpenErr != nil {
		return []string{}
	} else {
		ReadByte := make([]byte, 1024)
		for {
			over, ReadByteErr := lineInfo.Read(ReadByte)
			if over == 0 || ReadByteErr == io.EOF {
				break
			}
			var LineGet 队列
			err := json.Unmarshal(ReadByte[:over], &LineGet)
			if err != nil {
				return []string{}
			}
			return LineGet.Line
		}
	}
	return []string{}
}

func fakekeydump(KeyBordString chan string) {
	for {
		event := <-kbEventChanel
		vkCode := event.VkCode
		//fmt.Println(keyMap[vkCode])
		KeyBordString <- keyMap[vkCode]
		//close(KeyBordString)
		//fmt.Println("ces")
	}
}

func keyboardCallBack(nCode int, wParam win32.WPARAM, lParam win32.LPARAM) win32.LRESULT {
	if int(wParam) == win32.WM_KEYDOWN { //down
		kbd := (*win32.KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam))
		kbEventChanel <- KBEvent{
			VkCode:      kbd.VkCode,
			WindowText:  windowText,
			ProcessName: processName,
			ProcessId:   processId,
			Time:        time.Now(),
		}
	}
	res, _ := win32.CallNextHookEx(kbHook, nCode, wParam, lParam)
	return res
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	var FontString string
	dir, err := ioutil.ReadDir("./")
	if err != nil {
		return
	}
	for _, info := range dir {
		if strings.Contains(info.Name(), ".ttf") {
			FontString = info.Name()
		}
	}
	liColor := ""
	switch {
	case 0 < AllPrintColor && AllPrintColor < 7:
		liColor = []string{"#0644ff", "#12920e", "#3a96dd", "#ff1a2d", "#bb1fd3", "#c19c00"}[AllPrintColor-1]
	case 8 < AllPrintColor && AllPrintColor < 15:
		liColor = []string{"#3b78ff", "#16c60c", "#64dddd", "#e74856", "#b4009e", "#f9f1a5"}[AllPrintColor-9]
	default:
		liColor = "aqua"
	}

	htmlOne := "<head><meta charset=\"utf-8\"><style>@font-face {font-family:name;src: local('./Honkai-zh-cn.ttf'), url('http://127.0.0.1:100/font/" + FontString + "') format('woff');sRules}*{padding: 0px;margin: 0px;}li{list-style:"
	listyle := "\"none\""
	htmlTwo := ";font-family:name;}</style></head><body><ol id=\"father\" style=\"font-size: 40px;color: " + liColor + ";\">"
	var lihtml string
	for _, s := range lineup {
		lihtml += "<li>" + s + "</li>"
	}
	htmlThree := "</ol></body><script>function myrefresh(){window.location.reload();};setTimeout('myrefresh()',1000);</script>"
	html := htmlOne + listyle + htmlTwo + lihtml + htmlThree
	fmt.Fprint(w, html)
}

func WebServerTwo() {
	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/", indexHandler)
	serverMux.Handle("/font/", http.StripPrefix("/font/", http.FileServer(http.Dir("./"))))
	http.ListenAndServe(":100", serverMux)
}
