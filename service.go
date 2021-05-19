package main

import (
    "fmt"
    "time"
    "bufio"
	"io"
	"os"
	"strings"
    "strconv"
    "net/http"
    "encoding/base64"
    "encoding/json"
    "dpr/lib"
    "dpr/base"
    "github.com/satori/go.uuid"
)

var p int = 128;
var m int = 2;
var n int = 2
var q int = 521;
var filedir string = "file";

type JsonResult  struct{
    IsSuccess bool `json:"isSuccess"`
    Result interface{} `json:"result"`
    Log string `json:"log"`
}

func genSKFpart(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "invalid_http_method")
		return
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    seed := time.Now().UnixNano();
    seedStr := r.URL.Query().Get("seed");
    filename := r.URL.Query().Get("filename");
    if seedStr != "" {
        seed, _ = strconv.ParseInt(seedStr, 10, 64)
    }
    if filename == "" {
        filename = uuid.NewV4().String() + ".skf";
    }
    lib.GenSKFpart(seed, n, m, q, filedir + "/" + filename);
    fmt.Println(filename);
    jsonResult.IsSuccess = true;
    jsonResult.Result = "/getFile?filename=" + filename;
    jsonResultStr, err := json.Marshal(jsonResult)
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}

func genSKZpart(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "invalid_http_method")
		return
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    seed := time.Now().UnixNano();
    seedStr := r.URL.Query().Get("seed");
    hashstr := r.URL.Query().Get("hashstr");
    filename := r.URL.Query().Get("filename");
    if hashstr == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "hashstr can't be null";
    } else {
        if seedStr != "" {
            seed, _ = strconv.ParseInt(seedStr, 10, 64)
        }
        if filename == "" {
            filename = uuid.NewV4().String() + ".skz";
        }
        lib.GenSKZpart(seed, base.GetSM3(hashstr), m, q, filedir + "/" + filename);
        fmt.Println(filename);
        jsonResult.IsSuccess = true;
        jsonResult.Result = "/getFile?filename=" + filename;
    }
    jsonResultStr, err := json.Marshal(jsonResult)
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}

func composeSK(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "invalid_http_method")
		return
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    fpart := r.URL.Query().Get("fpart");
    zpart := r.URL.Query().Get("zpart");
    filename := r.URL.Query().Get("filename");
    if fpart == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "fpart can't be null";
    } else if zpart == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "zpart can't be null";
    } else {
        if filename == "" {
            filename = uuid.NewV4().String() + ".stk";
        }
        lib.ComposeSK(filedir + "/" + fpart, filedir + "/" + zpart, filedir + "/" + filename);
        fmt.Println(filename);
        jsonResult.IsSuccess = true;
        jsonResult.Result = "/getFile?filename=" + filename;
    }
    jsonResultStr, err := json.Marshal(jsonResult)
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}

func genSK(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "invalid_http_method")
		return
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    seed := time.Now().UnixNano();
    seedStr := r.URL.Query().Get("seed");
    filename := r.URL.Query().Get("filename");
    if seedStr != "" {
        seed, _ = strconv.ParseInt(seedStr, 10, 64)
    }
    if filename == "" {
        filename = uuid.NewV4().String() + ".stk";
    }
    lib.GenSK(seed, m, n, q, filedir + "/" + filename);
    fmt.Println(filename);
    jsonResult.IsSuccess = true;
    jsonResult.Result = "/getFile?filename=" + filename;
    jsonResultStr, err := json.Marshal(jsonResult)
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}

func genDictionary(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "invalid_http_method")
		return
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    skfile := r.URL.Query().Get("fpart");
    filename := r.URL.Query().Get("filename");
    if skfile == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "sk can't be null";
    } else {
        if filename == "" {
            filename = uuid.NewV4().String() + ".dict";
        }
        lib.GenDictionary(filedir + "/" + skfile, m, n, p, filedir + "/" + filename);
        fmt.Println(filename);
        jsonResult.IsSuccess = true;
        jsonResult.Result = "/getFile?filename=" + filename;
    }
    jsonResultStr, err := json.Marshal(jsonResult)
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}

func genTransferDictSS(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "invalid_http_method")
		return
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    sk_out := r.URL.Query().Get("sk_out");
    sk_in := r.URL.Query().Get("sk_in");
    filename := r.URL.Query().Get("filename");
    if sk_out == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "sk_out can't be null";
    } else if sk_in == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "sk_in can't be null";
    } else {
        if filename == "" {
            filename = uuid.NewV4().String() + ".tran";
        }
        lib.GenTransferDictSS(filedir + "/" + sk_out, filedir + "/" + sk_in, m, n, p, filedir + "/" + filename);
        fmt.Println(filename);
        jsonResult.IsSuccess = true;
        jsonResult.Result = "/getFile?filename=" + filename;
    }
    jsonResultStr, err := json.Marshal(jsonResult)
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}


func encString(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, "invalid_http_method")
		return
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    message := r.PostFormValue("message");
    skfile := r.PostFormValue("sk");
    if message == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "message can't be null";
    } else if skfile == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "sk can't be null";
    } else {
        bytes := lib.EncString(message, filedir + "/" + skfile, p);
        result := base64.StdEncoding.EncodeToString(bytes);
        fmt.Println(result);
        jsonResult.IsSuccess = true;
        jsonResult.Result = result;
    }
    jsonResultStr, err := json.Marshal(jsonResult)
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}

func decString(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed);
		fmt.Fprintf(w, "invalid_http_method");
		return;
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    cipherStr := r.PostFormValue("cipher");
    skfile := r.PostFormValue("sk");
    if cipherStr == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "cipher can't be null";
    } else if skfile == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "sk can't be null";
    } else {
        cipher, err := base64.StdEncoding.DecodeString(cipherStr);
        if err != nil {
            fmt.Println("base64.StdEncoding.DecodeString failed, err:", err);
            jsonResult.IsSuccess = false;
            jsonResult.Log = "cipher base64 decode error, check format";
        } else {
            result := lib.DecString(cipher, filedir + "/" + skfile);
            fmt.Println(result);
            jsonResult.IsSuccess = true;
            jsonResult.Result = result;
        }
    }
    jsonResultStr, err := json.Marshal(jsonResult);
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}

func sm3(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed);
		fmt.Fprintf(w, "invalid_http_method");
		return;
        }
    w.Header().Set("Content_Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    str := r.PostFormValue("str");
    res := lib.SM3(str);
    jsonResult.Result = res;
    jsonResultStr, err := json.Marshal(jsonResult);
    if err != nil {
                fmt.Println("json.marshal failed, err:", err);
                return;
        }
    w.Write(jsonResultStr);
}

func tranSS(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed);
		fmt.Fprintf(w, "invalid_http_method");
		return;
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    cipherStr := r.PostFormValue("cipher");
    trandict := r.PostFormValue("trandict");
    dict := r.PostFormValue("dict");
    if cipherStr == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "cipher can't be null";
    } else if trandict == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "trandict can't be null";
    } else if dict == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "dict can't be null";
    } else {
        cipher, err := base64.StdEncoding.DecodeString(cipherStr);
        if err != nil {
            fmt.Println("base64.StdEncoding.DecodeString failed, err:", err);
            jsonResult.IsSuccess = false;
            jsonResult.Log = "cipher base64 decode error, check format";
        } else {
            bytes := lib.TranSS(cipher, filedir + "/" + trandict, filedir + "/" + dict, p);
            result := base64.StdEncoding.EncodeToString(bytes);
            fmt.Println(result);
            jsonResult.IsSuccess = true;
            jsonResult.Result = result;
        }
    }
    jsonResultStr, err := json.Marshal(jsonResult);
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}

func equalString(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed);
		fmt.Fprintf(w, "invalid_http_method");
		return;
	}
    w.Header().Set("Content-Type","text/json");
    jsonResult := JsonResult {IsSuccess: true, Result: "", Log: ""};
    cipherStr1 := r.PostFormValue("cipher1");
    cipherStr2 := r.PostFormValue("cipher2");
    dict := r.PostFormValue("dict");
    trandict := r.PostFormValue("trandict");
    if cipherStr1 == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "cipher1 can't be null";
    } else if cipherStr2 == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "cipher2 can't be null";
    } else if dict == "" {
        jsonResult.IsSuccess = false;
        jsonResult.Log = "dict can't be null";
    } else if trandict == "" {
	jsonResult.IsSuccess = false;
	jsonResult.Log = "trandict can't be null";
    } else {
        cipher1, err1 := base64.StdEncoding.DecodeString(cipherStr1);
        cipher2, err2 := base64.StdEncoding.DecodeString(cipherStr2);
        if err1 != nil {
            fmt.Println("cipher1 base64.StdEncoding.DecodeString failed, err:", err1);
            jsonResult.IsSuccess = false;
            jsonResult.Log = "cipher1 base64 decode error, check format";
        } else if err2 != nil {
            fmt.Println("cipher2 base64.StdEncoding.DecodeString failed, err:", err2);
            jsonResult.IsSuccess = false;
            jsonResult.Log = "cipher2 base64 decode error, check format";
        } else {
            result := lib.EqualString(cipher1, cipher2, filedir + "/" + dict, filedir + "/" + trandict, p);
            fmt.Println(result);
            jsonResult.IsSuccess = true;
            jsonResult.Result = result;
        }
    }
    jsonResultStr, err := json.Marshal(jsonResult);
    if err != nil {
		fmt.Println("json.marshal failed, err:", err);
		return;
	}
    w.Write(jsonResultStr);
}

func getFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query()["filename"][0]
    if filename == "" {
        w.Header().Set("Content-Type","Mime-Type");
        jsonResult := JsonResult {IsSuccess: false, Result: "", Log: "filename can't be null"};
        jsonResultStr, _ := json.Marshal(jsonResult);
        w.Write(jsonResultStr);
    } else {
        file, _ := os.Open(filedir + "/" + filename);
        defer file.Close();
        fileHeader := make([]byte, 512)
        file.Read(fileHeader)
        fileStat, _ := file.Stat()
        w.Header().Set("Content-Disposition", "attachment; filename=" + filename)
        w.Header().Set("Content-Type", http.DetectContentType(fileHeader))
        w.Header().Set("Content-Length", strconv.FormatInt(fileStat.Size(), 10))
        file.Seek(0, 0)
        io.Copy(w, file)
    }
    return
}

//读取key=value类型的配置文件
func InitConfig(path string) map[string]string {
	config := make(map[string]string)
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		panic(err)
	}
	r := bufio.NewReader(f)
	for {
		b, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
        s := strings.TrimSpace(string(b))
        fmt.Println(s);
		index := strings.Index(s, "=")
		if index < 0 {
			continue
		}
		key := strings.TrimSpace(s[:index])
		if len(key) == 0 {
			continue
		}
		value := strings.TrimSpace(s[index+1:])
		if len(value) == 0 {
			continue
		}
		config[key] = value
	}
	return config
}

func main() {
    fmt.Println("读取配置文件..");
    config := InitConfig("config.properties")
    os.Mkdir(filedir, os.ModePerm);
    fmt.Println("服务启动..");
    http.HandleFunc("/km/genSKFpart", genSKFpart);
    http.HandleFunc("/km/genSKZpart", genSKZpart);
    http.HandleFunc("/km/composeSK", composeSK);
    http.HandleFunc("/km/genSK", genSK);
    http.HandleFunc("/km/genDictionary", genDictionary);
    http.HandleFunc("/km/genTransferDictSS", genTransferDictSS);

    http.HandleFunc("/enc/encString", encString);
    http.HandleFunc("/enc/decString", decString);
    http.HandleFunc("/enc/sm3", sm3);

    http.HandleFunc("/opt/tranSS", tranSS);
    http.HandleFunc("/opt/equalString", equalString);

    http.HandleFunc("/getFile", getFile);

    http.ListenAndServe("0.0.0.0:" + config["port"], nil);
    fmt.Println("服务启动成功。");
}
