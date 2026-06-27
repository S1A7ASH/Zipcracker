package main

import (
    "bufio"
    "fmt"
    "os"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"
    "github.com/yeka/zip"
)

const (
    Reset  = "\033[0m"
    Red    = "\033[31m"
    Green  = "\033[32m"
    Yellow = "\033[33m"
    Blue   = "\033[34m"
    Purple = "\033[35m"
    Cyan   = "\033[36m"
    Bold   = "\033[1m"
)

type CPULimiter struct {
    targetCPU  float64
    lastCheck  time.Time
    sleepTime  time.Duration
    mu         sync.Mutex
}

func NewCPULimiter(targetPercent float64) *CPULimiter {
    return &CPULimiter{
        targetCPU: targetPercent,
        lastCheck: time.Now(),
    }
}

func (cl *CPULimiter) throttle() {
    cl.mu.Lock()
    defer cl.mu.Unlock()
    
    if time.Since(cl.lastCheck) < 100*time.Millisecond {
        return
    }
    
    workRatio := cl.targetCPU / 100.0
    cl.sleepTime = time.Duration(float64(time.Millisecond) * (1 - workRatio) * 100)
    
    cl.lastCheck = time.Now()
    
    if cl.sleepTime > 0 {
        time.Sleep(cl.sleepTime)
    }
}

type ZipCracker struct {
    zipPath      string
    wordlistPath string
    threads      int
    cpuLimit     float64
    found        int32
    attempts     uint64
    password     string
    startTime    time.Time
    mu           sync.Mutex
    cpuLimiter   *CPULimiter
}

func NewZipCracker(zipPath, wordlistPath string, threads int, cpuLimit float64) *ZipCracker {
    return &ZipCracker{
        zipPath:      zipPath,
        wordlistPath: wordlistPath,
        threads:      threads,
        cpuLimit:     cpuLimit,
        cpuLimiter:   NewCPULimiter(cpuLimit),
    }
}

func (c *ZipCracker) printBanner() {
    fmt.Printf("%s%s%s\n", Cyan, strings.Repeat("=", 60), Reset)
    fmt.Printf("%s   BlackCat ZIP Password Cracker  %s\n", Bold+Yellow, Reset)
    fmt.Printf("%s%s%s\n", Cyan, strings.Repeat("=", 60), Reset)
    fmt.Printf("%sZIP File   :%s %s\n", Blue, Reset, c.zipPath)
    fmt.Printf("%sWordlist   :%s %s\n", Blue, Reset, c.wordlistPath)
    fmt.Printf("%sThreads    :%s %d\n", Blue, Reset, c.threads)
    fmt.Printf("%sCPU Limit  :%s %.0f%%\n", Blue, Reset, c.cpuLimit)
    fmt.Printf("%s%s%s\n\n", Cyan, strings.Repeat("=", 60), Reset)
}

func (c *ZipCracker) tryPassword(password string) bool {
    zf, err := zip.OpenReader(c.zipPath)
    if err != nil {
        return false
    }
    defer zf.Close()
    
    for _, f := range zf.File {
        if f.IsEncrypted() {
            f.SetPassword(password)
            rc, err := f.Open()
            if err != nil {
                return false
            }
            
            buf := make([]byte, 64)
            _, err = rc.Read(buf)
            rc.Close()
            
            if err == nil {
                return true
            }
            return false
        }
    }
    return false
}

func (c *ZipCracker) worker(id int, passwords <-chan string, wg *sync.WaitGroup) {
    defer wg.Done()
    
    localAttempts := uint64(0)
    
    for password := range passwords {
        if atomic.LoadInt32(&c.found) == 1 {
            return
        }
        
        if localAttempts%50 == 0 {
            c.cpuLimiter.throttle()
        }
        
        if c.tryPassword(password) {
            c.mu.Lock()
            c.password = password
            c.mu.Unlock()
            atomic.StoreInt32(&c.found, 1)
            
            fmt.Printf("\n\n")
            fmt.Printf("%s%s%s\n", Green, strings.Repeat("*", 60), Reset)
            fmt.Printf("%s%s%s\n", Bold+Green, strings.Repeat(" ", 20)+"PASSWORD FOUND!", Reset)
            fmt.Printf("%s%s%s\n", Green, strings.Repeat("*", 60), Reset)
            fmt.Printf("\n%sCorrect Password:%s %s%s%s\n", Bold+Yellow, Reset, Bold+Red, password, Reset)
            fmt.Printf("\n%s%s%s\n\n", Green, strings.Repeat("*", 60), Reset)
            return
        }
        
        localAttempts++
        
        if localAttempts%500 == 0 {
            atomic.AddUint64(&c.attempts, 500)
            localAttempts = 0
        }
    }
    
    atomic.AddUint64(&c.attempts, localAttempts)
}

func (c *ZipCracker) progressReporter(done chan bool) {
    fmt.Printf("%s[*] Starting crack operation...%s\n\n", Cyan, Reset)
    
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()
    
    var lastAttempts uint64
    
    for {
        select {
        case <-done:
            return
        case <-ticker.C:
            if atomic.LoadInt32(&c.found) == 1 {
                return
            }
            
            attempts := atomic.LoadUint64(&c.attempts)
            elapsed := time.Since(c.startTime).Seconds()
            
            var speed float64
            if elapsed > 0 {
                speed = float64(attempts) / elapsed
            }
            
            instantSpeed := float64(attempts-lastAttempts) / 0.5
            lastAttempts = attempts
            
            fmt.Printf("\r%s[*]%s Speed: %s%8.0f%s (instant: %s%6.0f%s) | "+
                "Tested: %s%10d%s | "+
                "Time: %s%6.1f%ss | "+
                "CPU: %s%.0f%%%s      ",
                Purple, Reset,
                Green, speed, Reset,
                Yellow, instantSpeed, Reset,
                Yellow, attempts, Reset,
                Cyan, elapsed, Reset,
                Blue, c.cpuLimit, Reset)
        }
    }
}

func (c *ZipCracker) Crack() (string, error) {
    c.printBanner()
    
    if _, err := os.Stat(c.zipPath); os.IsNotExist(err) {
        return "", fmt.Errorf("ZIP file not found: %s", c.zipPath)
    }
    
    if _, err := os.Stat(c.wordlistPath); os.IsNotExist(err) {
        return "", fmt.Errorf("wordlist file not found: %s", c.wordlistPath)
    }
    
    file, err := os.Open(c.wordlistPath)
    if err != nil {
        return "", fmt.Errorf("error opening wordlist: %v", err)
    }
    defer file.Close()
    
    runtime.GOMAXPROCS(c.threads)
    
    passwords := make(chan string, c.threads*1000)
    var wg sync.WaitGroup
    
    c.startTime = time.Now()
    
    for i := 0; i < c.threads; i++ {
        wg.Add(1)
        go c.worker(i, passwords, &wg)
    }
    
    done := make(chan bool)
    go c.progressReporter(done)
    
    fmt.Printf("%s[*] Loading wordlist...%s\n", Cyan, Reset)
    
    scanner := bufio.NewScanner(file)
    scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
    
    lineCount := 0
    for scanner.Scan() {
        if atomic.LoadInt32(&c.found) == 1 {
            break
        }
        
        password := strings.TrimSpace(scanner.Text())
        if password == "" {
            continue
        }
        
        passwords <- password
        lineCount++
        
        if lineCount%100000 == 0 {
            fmt.Printf("\r%s[*] Loaded: %d lines%s", Purple, lineCount, Reset)
        }
    }
    
    fmt.Printf("\r%s[+] Loaded: %d passwords%s\n", Green, lineCount, Reset)
    
    close(passwords)
    wg.Wait()
    close(done)
    
    elapsed := time.Since(c.startTime)
    
    fmt.Printf("\n\n")
    
    if c.found == 1 {
        fmt.Printf("%s%s%s\n", Green, strings.Repeat("-", 60), Reset)
        fmt.Printf("%s[+] Crack completed successfully!%s\n", Bold+Green, Reset)
        fmt.Printf("%s%s%s\n", Green, strings.Repeat("-", 60), Reset)
        fmt.Printf("%sTime      :%s %.2f seconds\n", Yellow, Reset, elapsed.Seconds())
        fmt.Printf("%sAttempts  :%s %d\n", Yellow, Reset, atomic.LoadUint64(&c.attempts))
        fmt.Printf("%sSpeed     :%s %.0f passwords/sec\n", Yellow, Reset, 
            float64(atomic.LoadUint64(&c.attempts))/elapsed.Seconds())
        fmt.Printf("%sPassword  :%s %s%s%s\n", Yellow, Reset, Bold+Red, c.password, Reset)
        fmt.Printf("%s%s%s\n", Green, strings.Repeat("-", 60), Reset)
        
        return c.password, nil
    } else {
        fmt.Printf("%s%s%s\n", Red, strings.Repeat("-", 60), Reset)
        fmt.Printf("%s[-] Password not found in wordlist%s\n", Bold+Red, Reset)
        fmt.Printf("%s%s%s\n", Red, strings.Repeat("-", 60), Reset)
        fmt.Printf("%sTime      :%s %.2f seconds\n", Yellow, Reset, elapsed.Seconds())
        fmt.Printf("%sAttempts  :%s %d\n", Yellow, Reset, atomic.LoadUint64(&c.attempts))
        fmt.Printf("%sSpeed     :%s %.0f passwords/sec\n", Yellow, Reset, 
            float64(atomic.LoadUint64(&c.attempts))/elapsed.Seconds())
        fmt.Printf("%s%s%s\n", Red, strings.Repeat("-", 60), Reset)
        
        return "", fmt.Errorf("password not found")
    }
}

func getInput(prompt string) string {
    reader := bufio.NewReader(os.Stdin)
    fmt.Printf("%s%s%s", Cyan, prompt, Reset)
    input, _ := reader.ReadString('\n')
    return strings.TrimSpace(input)
}

func main() {
    fmt.Printf("%s%s%s\n", Cyan, strings.Repeat("=", 60), Reset)
    fmt.Printf("%s   BlackCat ZIP Password Cracker  %s\n", Bold+Yellow, Reset)
    fmt.Printf("%s%s%s\n\n", Cyan, strings.Repeat("=", 60), Reset)
    
    zipPath := getInput("Enter ZIP file path: ")
    for zipPath == "" {
        fmt.Printf("%s[!] ZIP file path cannot be empty%s\n", Red, Reset)
        zipPath = getInput("Enter ZIP file path: ")
    }
    
    if _, err := os.Stat(zipPath); os.IsNotExist(err) {
        fmt.Printf("%s[!] Error: ZIP file not found: %s%s\n", Red, zipPath, Reset)
        fmt.Printf("%sPress Enter to exit...%s", Yellow, Reset)
        bufio.NewReader(os.Stdin).ReadBytes('\n')
        os.Exit(1)
    }
    
    wordlistPath := getInput("Enter wordlist file path: ")
    for wordlistPath == "" {
        fmt.Printf("%s[!] Wordlist file path cannot be empty%s\n", Red, Reset)
        wordlistPath = getInput("Enter wordlist file path: ")
    }
    
    if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
        fmt.Printf("%s[!] Error: wordlist file not found: %s%s\n", Red, wordlistPath, Reset)
        fmt.Printf("%sPress Enter to exit...%s", Yellow, Reset)
        bufio.NewReader(os.Stdin).ReadBytes('\n')
        os.Exit(1)
    }
    
    threadsStr := getInput("Enter number of threads (default 4): ")
    threads := 4
    if threadsStr != "" {
        if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
            threads = t
        } else {
            fmt.Printf("%s[!] Invalid input, using default: 4%s\n", Yellow, Reset)
        }
    }
    
    cpuLimitStr := getInput("Enter CPU limit in percent (default 30): ")
    cpuLimit := 30.0
    if cpuLimitStr != "" {
        if c, err := strconv.ParseFloat(cpuLimitStr, 64); err == nil && c > 0 && c <= 100 {
            cpuLimit = c
        } else {
            fmt.Printf("%s[!] Invalid input, using default: 30%%%s\n", Yellow, Reset)
        }
    }
    
    fmt.Printf("\n")
    
    cracker := NewZipCracker(zipPath, wordlistPath, threads, cpuLimit)
    
    password, err := cracker.Crack()
    
    if err != nil {
        fmt.Printf("\n%s[!] %v%s\n", Red, err, Reset)
        fmt.Printf("\n%sPress Enter to exit...%s", Yellow, Reset)
        bufio.NewReader(os.Stdin).ReadBytes('\n')
        os.Exit(1)
    }
    
    resultFile := "password_found.txt"
    if err := os.WriteFile(resultFile, []byte(fmt.Sprintf("Password: %s\nTime: %s\n", 
        password, time.Since(cracker.startTime).String())), 0644); err == nil {
        fmt.Printf("\n%s[+] Password saved to '%s'%s\n", Green, resultFile, Reset)
    }
    
    fmt.Printf("\n%s[+] Done!%s\n", Bold+Green, Reset)
    fmt.Printf("\n%sPress Enter to exit...%s", Yellow, Reset)
    bufio.NewReader(os.Stdin).ReadBytes('\n')
}