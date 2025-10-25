// lockbox.go
// Features: custom container format, PBKDF2, AES-GCM, gzip compression, checksum,
// secure-delete, recursive+filters, rename pattern, parallelism, dry-run, verbose/quiet, logging.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

var magicHeader = []byte("IMGENC1\x00") // 8 bytes magic

type metadata struct {
	OriginalName string `json:"original_name"`
	Compressed   bool   `json:"compressed"`
	Checksum     string `json:"checksum"`   // sha256 hex of stored bytes (compressed if compressed)
	Salt         string `json:"salt"`       // hex
	Iterations   int    `json:"iterations"` // PBKDF2 iterations
	HashAlgo     string `json:"hash_algo"`  // sha256 or sha512
}

type Options struct {
	Password       string
	KeyFile        string
	UseKeyFile     bool
	SaltHex        string
	SaltRandom     bool
	Iterations     int
	HashAlgo       string
	Compress       bool
	SecureDelete   bool
	RemoveOriginal bool
	OutputDir      string
	Suffix         string
	RenamePattern  string
	Parallel       int
	DryRun         bool
	Progress       bool
	Verbose        bool
	Quiet          bool
	Overwrite      bool
	Include        []string
	Exclude        []string
	Recursive      bool
	LogPath        string
	KeepExt        bool // For decrypt: keep original name without adding _decrypted
}

type job struct {
	Path string
}

func readLine(prompt string) string {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	s, _ := r.ReadString('\n')
	return strings.TrimSpace(s)
}

func readYesNo(prompt string, def bool) bool {
	defStr := "n"
	if def {
		defStr = "y"
	}
	for {
		in := readLine(fmt.Sprintf("%s (y/n) [%s]: ", prompt, defStr))
		if in == "" {
			return def
		}
		in = strings.ToLower(in)
		if in == "y" || in == "yes" {
			return true
		} else if in == "n" || in == "no" {
			return false
		}
		fmt.Println("Invalid input. Please enter y or n.")
	}
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

func readPasswordWithConfirm(prompt string) (string, error) {
	for {
		pw1, err := readPassword(prompt)
		if err != nil {
			return "", err
		}
		pw2, err := readPassword("Confirm " + prompt)
		if err != nil {
			return "", err
		}
		if pw1 == pw2 {
			return pw1, nil
		}
		fmt.Println("Passwords do not match. Please try again.")
	}
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// PBKDF2 inline (HMAC + Hash)
func pbkdf2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	hLen := h().Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(h, password)
		mac.Write(salt)
		var intBlock [4]byte
		binary.BigEndian.PutUint32(intBlock[:], uint32(block))
		mac.Write(intBlock[:])
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac = hmac.New(h, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := 0; j < len(t); j++ {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func deriveKeyFromPassword(password string, salt []byte, iterations int, hashAlgo string) ([]byte, error) {
	var h func() hash.Hash
	switch strings.ToLower(hashAlgo) {
	case "sha256":
		h = sha256.New
	case "sha512":
		h = sha512.New
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashAlgo)
	}
	return pbkdf2([]byte(password), salt, iterations, 32, h), nil // AES-256 key
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func secureDelete(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	size := info.Size()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 4096)
	var written int64
	for written < size {
		toWrite := int64(len(buf))
		if size-written < toWrite {
			toWrite = size - written
		}
		_, _ = rand.Read(buf[:toWrite])
		if _, err := f.Write(buf[:toWrite]); err != nil {
			return err
		}
		written += toWrite
	}
	f.Sync()
	f.Close()
	return os.Remove(path)
}

// expandPath expands ~ to home directory and resolves relative paths
func expandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[1:])
	}
	return filepath.Abs(path)
}

// browseDirectory allows interactive directory selection
func browseDirectory() (string, error) {
	current, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		fmt.Printf("\nCurrent directory: %s\n", current)
		fmt.Println("Options: [1] List directories, [2] List files, [3] Enter path, [4] Select this directory, [5] Go up, [6] Home, [7] Desktop, [8] Pictures")
		choice := readLine("Choice: ")
		switch choice {
		case "1":
			dirs, err := listDirectories(current)
			if err != nil {
				fmt.Printf("Error listing directories: %v\n", err)
				continue
			}
			if len(dirs) == 0 {
				fmt.Println("No subdirectories found.")
				continue
			}
			fmt.Println("Directories:")
			for i, dir := range dirs {
				fmt.Printf(" %d) %s\n", i+1, dir)
			}
			num := readLine("Select directory number (or enter to go back): ")
			if num == "" {
				continue
			}
			n, err := strconv.Atoi(num)
			if err != nil || n < 1 || n > len(dirs) {
				fmt.Println("Invalid selection.")
				continue
			}
			current = filepath.Join(current, dirs[n-1])
		case "2":
			files, err := listFiles(current)
			if err != nil {
				fmt.Printf("Error listing files: %v\n", err)
				continue
			}
			if len(files) == 0 {
				fmt.Println("No files found.")
				continue
			}
			fmt.Println("Files:")
			for i, file := range files {
				fmt.Printf(" %d) %s\n", i+1, file)
			}
			num := readLine("Select file number (or enter to go back): ")
			if num == "" {
				continue
			}
			n, err := strconv.Atoi(num)
			if err != nil || n < 1 || n > len(files) {
				fmt.Println("Invalid selection.")
				continue
			}
			return filepath.Join(current, files[n-1]), nil
		case "3":
			path := readLine("Enter full path (or drag-and-drop from file explorer): ")
			if path == "" {
				continue
			}
			expanded, err := expandPath(path)
			if err != nil {
				fmt.Printf("Invalid path: %v\n", err)
				continue
			}
			if info, err := os.Stat(expanded); err == nil {
				if info.IsDir() {
					current = expanded
				} else {
					return expanded, nil
				}
			} else {
				fmt.Printf("Path does not exist: %v\n", err)
			}
		case "4":
			return current, nil
		case "5":
			parent := filepath.Dir(current)
			if parent == current {
				fmt.Println("Already at root directory.")
				continue
			}
			current = parent
		case "6":
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Printf("Error accessing home directory: %v\n", err)
				continue
			}
			current = home
		case "7":
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Printf("Error accessing home directory: %v\n", err)
				continue
			}
			current = filepath.Join(home, "Desktop")
			if _, err := os.Stat(current); err != nil {
				fmt.Println("Desktop directory not found.")
				continue
			}
		case "8":
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Printf("Error accessing home directory: %v\n", err)
				continue
			}
			current = filepath.Join(home, "Pictures")
			if _, err := os.Stat(current); err != nil {
				fmt.Println("Pictures directory not found.")
				continue
			}
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

// listDirectories returns a list of subdirectories in the given path
func listDirectories(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}
	return dirs, nil
}

// listFiles returns a list of files in the given path
func listFiles(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

// collectPaths allows selecting files or directories with wildcards
func collectPaths() ([]string, error) {
	var paths []string
	fmt.Println("\nSelect files or directories:")
	fmt.Println("1) Enter paths manually (comma-separated, e.g., photo.jpg,*.jpg)")
	fmt.Println("2) Browse directories and select files")
	fmt.Println("3) Quick select: Desktop")
	fmt.Println("4) Quick select: Pictures")
	choice := readLine("Choice: ")
	switch choice {
	case "1":
		fmt.Println("Enter paths (comma-separated, supports *.jpg, *.png, etc., or drag-and-drop)")
		input := readLine("Paths: ")
		if input == "" {
			return nil, nil
		}
		for _, p := range splitAndTrim(input) {
			expanded, err := expandPath(p)
			if err != nil {
				fmt.Printf("Invalid path %s: %v\n", p, err)
				continue
			}
			if strings.Contains(expanded, "*") {
				matches, err := filepath.Glob(expanded)
				if err != nil {
					fmt.Printf("Error expanding wildcard %s: %v\n", p, err)
					continue
				}
				paths = append(paths, matches...)
			} else {
				paths = append(paths, expanded)
			}
		}
	case "2":
		path, err := browseDirectory()
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	case "3":
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		desktop := filepath.Join(home, "Desktop")
		if _, err := os.Stat(desktop); err != nil {
			return nil, fmt.Errorf("Desktop directory not found")
		}
		paths = append(paths, desktop)
	case "4":
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		pictures := filepath.Join(home, "Pictures")
		if _, err := os.Stat(pictures); err != nil {
			return nil, fmt.Errorf("Pictures directory not found")
		}
		paths = append(paths, pictures)
	default:
		return nil, fmt.Errorf("invalid choice")
	}
	if len(paths) == 0 {
		return nil, nil
	}
	return paths, nil
}

// selectOutputDir allows interactive selection of the output directory
func selectOutputDir(currentDir string) (string, error) {
	fmt.Printf("\nSelect output directory (current: %s):\n", currentDir)
	fmt.Println("1) Keep current directory")
	fmt.Println("2) Browse directories")
	fmt.Println("3) Quick select: Desktop")
	fmt.Println("4) Quick select: Pictures")
	fmt.Println("5) Enter path manually")
	choice := readLine("Choice: ")
	switch choice {
	case "1":
		return "", nil // Keep current directory
	case "2":
		path, err := browseDirectory()
		if err != nil {
			return "", err
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			return "", fmt.Errorf("selected path is not a directory: %s", path)
		}
		return path, nil
	case "3":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		desktop := filepath.Join(home, "Desktop")
		if _, err := os.Stat(desktop); err != nil {
			return "", fmt.Errorf("Desktop directory not found")
		}
		return desktop, nil
	case "4":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		pictures := filepath.Join(home, "Pictures")
		if _, err := os.Stat(pictures); err != nil {
			return "", fmt.Errorf("Pictures directory not found")
		}
		return pictures, nil
	case "5":
		path := readLine("Enter output directory path (or drag-and-drop): ")
		if path == "" {
			return "", nil // Keep current directory
		}
		expanded, err := expandPath(path)
		if err != nil {
			return "", fmt.Errorf("invalid path: %v", err)
		}
		if info, err := os.Stat(expanded); err != nil || !info.IsDir() {
			return "", fmt.Errorf("path is not a directory or does not exist: %s", expanded)
		}
		return expanded, nil
	default:
		return "", fmt.Errorf("invalid choice")
	}
}

func encryptBytes(plaintext []byte, password string, salt []byte, iterations int, hashAlgo string, compress bool) ([]byte, metadata, error) {
	meta := metadata{
		OriginalName: "",
		Compressed:   compress,
		Checksum:     "",
		Salt:         hex.EncodeToString(salt),
		Iterations:   iterations,
		HashAlgo:     hashAlgo,
	}
	var dataToStore []byte
	if compress {
		var b bytes.Buffer
		gw := gzip.NewWriter(&b)
		if _, err := gw.Write(plaintext); err != nil {
			return nil, meta, err
		}
		if err := gw.Close(); err != nil {
			return nil, meta, err
		}
		dataToStore = b.Bytes()
	} else {
		dataToStore = plaintext
	}
	meta.Checksum = sha256Hex(dataToStore)
	key, err := deriveKeyFromPassword(password, salt, iterations, hashAlgo)
	if err != nil {
		return nil, meta, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, meta, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, meta, err
	}
	nonce, err := randBytes(gcm.NonceSize())
	if err != nil {
		return nil, meta, err
	}
	ct := gcm.Seal(nil, nonce, dataToStore, nil)
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, meta, err
	}
	var out bytes.Buffer
	out.Write(magicHeader)
	var metaLen uint32 = uint32(len(metaBytes))
	binary.Write(&out, binary.BigEndian, metaLen)
	out.Write(metaBytes)
	out.WriteByte(byte(len(nonce)))
	out.Write(nonce)
	out.Write(ct)
	return out.Bytes(), meta, nil
}

func decryptBytes(enc []byte, password string) ([]byte, metadata, error) {
	if len(enc) < len(magicHeader) {
		return nil, metadata{}, fmt.Errorf("file too small or not a valid lockbox file")
	}
	if !bytes.Equal(enc[:len(magicHeader)], magicHeader) {
		return nil, metadata{}, fmt.Errorf("bad magic header")
	}
	r := bytes.NewReader(enc[len(magicHeader):])
	var metaLen uint32
	if err := binary.Read(r, binary.BigEndian, &metaLen); err != nil {
		return nil, metadata{}, err
	}
	metaBytes := make([]byte, metaLen)
	if _, err := io.ReadFull(r, metaBytes); err != nil {
		return nil, metadata{}, err
	}
	var meta metadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, metadata{}, err
	}
	nonceLenB := make([]byte, 1)
	if _, err := io.ReadFull(r, nonceLenB); err != nil {
		return nil, metadata{}, err
	}
	nonceLen := int(nonceLenB[0])
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, metadata{}, err
	}
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return nil, metadata{}, err
	}
	salt, err := hex.DecodeString(meta.Salt)
	if err != nil {
		return nil, metadata{}, err
	}
	key, err := deriveKeyFromPassword(password, salt, meta.Iterations, meta.HashAlgo)
	if err != nil {
		return nil, meta, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, meta, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, meta, err
	}
	plainStored, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, meta, fmt.Errorf("decryption/auth failed: %w", err)
	}
	var final []byte
	if meta.Compressed {
		gr, err := gzip.NewReader(bytes.NewReader(plainStored))
		if err != nil {
			return nil, meta, err
		}
		final, err = io.ReadAll(gr)
		if err := gr.Close(); err != nil {
			return nil, meta, err
		}
		if err != nil {
			return nil, meta, err
		}
	} else {
		final = plainStored
	}
	return final, meta, nil
}

func isImageExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".webp":
		return true
	default:
		return false
	}
}

func normalizeExt(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if !strings.HasPrefix(s, ".") {
		s = "." + s
	}
	return strings.ToLower(s)
}

func matchesIncludeExclude(path string, opts *Options) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if len(opts.Include) > 0 {
		ok := false
		for _, x := range opts.Include {
			if x == "" {
				continue
			}
			if x == ext || x == strings.TrimPrefix(ext, ".") {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(opts.Exclude) > 0 {
		for _, x := range opts.Exclude {
			if x == "" {
				continue
			}
			if x == ext || x == strings.TrimPrefix(ext, ".") {
				return false
			}
		}
	}
	return true
}

func walkFiles(args []string, opts *Options, isEncrypt bool) ([]string, error) {
	var out []string
	for _, a := range args {
		info, err := os.Stat(a)
		if err != nil {
			return nil, fmt.Errorf("error accessing %s: %v", a, err)
		}
		if info.IsDir() {
			if opts.Recursive {
				err := filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if d.IsDir() {
						return nil
					}
					if len(opts.Include) == 0 && len(opts.Exclude) == 0 {
						if isEncrypt && !isImageExt(p) {
							return nil
						}
					}
					if !matchesIncludeExclude(p, opts) {
						return nil
					}
					out = append(out, p)
					return nil
				})
				if err != nil {
					return nil, err
				}
			} else {
				ents, err := os.ReadDir(a)
				if err != nil {
					return nil, err
				}
				for _, e := range ents {
					if e.IsDir() {
						continue
					}
					p := filepath.Join(a, e.Name())
					if len(opts.Include) == 0 && len(opts.Exclude) == 0 {
						if isEncrypt && !isImageExt(p) {
							continue
						}
					}
					if !matchesIncludeExclude(p, opts) {
						continue
					}
					out = append(out, p)
				}
			}
		} else {
			if len(opts.Include) == 0 && len(opts.Exclude) == 0 {
				if isEncrypt && !isImageExt(a) {
					continue
				}
			}
			if !matchesIncludeExclude(a, opts) {
				continue
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// process single encrypt
func processEncryptFile(path string, opts *Options, logf *os.File) error {
	if opts.DryRun {
		fmt.Printf("[dry] encrypt: %s\n", path)
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var salt []byte
	if opts.SaltRandom || opts.SaltHex == "" {
		salt, err = randBytes(16)
		if err != nil {
			return err
		}
	} else {
		salt, err = hex.DecodeString(opts.SaltHex)
		if err != nil {
			return fmt.Errorf("bad salt: %v", err)
		}
	}
	outName := filepath.Base(path) + opts.Suffix
	if opts.RenamePattern != "" {
		orig := filepath.Base(path)
		name := strings.TrimSuffix(orig, filepath.Ext(orig))
		ext := filepath.Ext(orig)
		p := strings.ReplaceAll(opts.RenamePattern, "{name}", name)
		p = strings.ReplaceAll(p, "{ext}", ext)
		outName = p
	}
	outPath := filepath.Join(opts.OutputDir, outName)
	if opts.OutputDir != "." {
		if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}
	}
	if !opts.Overwrite {
		if _, err := os.Stat(outPath); err == nil {
			return fmt.Errorf("file exists: %s (use overwrite option to replace)", outPath)
		}
	}
	encBytes, meta, err := encryptBytes(data, opts.GetPassword(), salt, opts.Iterations, opts.HashAlgo, opts.Compress)
	if err != nil {
		return err
	}
	meta.OriginalName = filepath.Base(path)
	metaBytes, _ := json.Marshal(meta)
	var final bytes.Buffer
	final.Write(magicHeader)
	var metaLen uint32 = uint32(len(metaBytes))
	binary.Write(&final, binary.BigEndian, metaLen)
	final.Write(metaBytes)
	offset := len(magicHeader)
	oldMetaLen := int(binary.BigEndian.Uint32(encBytes[offset : offset+4]))
	offset += 4 + oldMetaLen
	nonceLen := int(encBytes[offset])
	offset++
	nonce := encBytes[offset : offset+nonceLen]
	offset += nonceLen
	ct := encBytes[offset:]
	final.WriteByte(byte(len(nonce)))
	final.Write(nonce)
	final.Write(ct)
	if err := os.WriteFile(outPath, final.Bytes(), 0o644); err != nil {
		return err
	}
	if opts.Verbose {
		fmt.Printf("Encrypted %s -> %s (compressed: %v, checksum: %s)\n", path, outPath, meta.Compressed, meta.Checksum)
	} else if !opts.Quiet {
		fmt.Printf("Encrypted: %s -> %s\n", path, outPath)
	}
	if opts.SecureDelete {
		if err := secureDelete(path); err != nil {
			fmt.Printf("Warning: secure-delete failed for %s: %v\n", path, err)
		}
	} else if opts.RemoveOriginal {
		if err := os.Remove(path); err != nil {
			fmt.Printf("Warning: remove original failed for %s: %v\n", path, err)
		}
	}
	if logf != nil {
		fmt.Fprintf(logf, "%s ENCRYPT %s -> %s\n", time.Now().Format(time.RFC3339), path, outPath)
	}
	return nil
}

func processDecryptFile(path string, opts *Options, logf *os.File) error {
	if opts.DryRun {
		fmt.Printf("[dry] decrypt: %s\n", path)
		return nil
	}
	in, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	plain, meta, err := decryptBytes(in, opts.GetPassword())
	if err != nil {
		return err
	}
	if !opts.Quiet {
		if !meta.Compressed {
			if sha256Hex(plain) != meta.Checksum {
				fmt.Printf("Warning: checksum mismatch for %s\n", path)
			}
		}
	}
	origName := meta.OriginalName
	if origName == "" {
		origName = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	outName := origName
	if opts.RenamePattern != "" {
		name := strings.TrimSuffix(origName, filepath.Ext(origName))
		ext := filepath.Ext(origName)
		p := strings.ReplaceAll(opts.RenamePattern, "{name}", name)
		p = strings.ReplaceAll(p, "{ext}", ext)
		outName = p
	} else if !opts.KeepExt {
		ext := filepath.Ext(origName)
		name := strings.TrimSuffix(origName, ext)
		outName = name + "_decrypted" + ext
	}
	outPath := filepath.Join(opts.OutputDir, outName)
	if opts.OutputDir != "." {
		if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory: %v", err)
		}
	}
	if !opts.Overwrite {
		if _, err := os.Stat(outPath); err == nil {
			return fmt.Errorf("file exists: %s (use overwrite option)", outPath)
		}
	}
	if err := os.WriteFile(outPath, plain, 0o644); err != nil {
		return err
	}
	if opts.Verbose {
		fmt.Printf("Decrypted %s -> %s (original: %s)\n", path, outPath, meta.OriginalName)
	} else if !opts.Quiet {
		fmt.Printf("Decrypted: %s -> %s\n", path, outPath)
	}
	if opts.SecureDelete {
		if err := secureDelete(path); err != nil {
			fmt.Printf("Warning: secure-delete failed for %s: %v\n", path, err)
		}
	} else if opts.RemoveOriginal {
		if err := os.Remove(path); err != nil {
			fmt.Printf("Warning: remove original failed for %s: %v\n", path, err)
		}
	}
	if logf != nil {
		fmt.Fprintf(logf, "%s DECRYPT %s -> %s\n", time.Now().Format(time.RFC3339), path, outPath)
	}
	return nil
}

func runWorkerPool(paths []string, encrypt bool, opts *Options) error {
	var logf *os.File
	if opts.LogPath != "" {
		var err error
		logf, err = os.OpenFile(opts.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %v", err)
		}
		defer logf.Close()
	}
	n := opts.Parallel
	if n <= 0 {
		n = runtime.NumCPU()
	}
	jobs := make(chan string, len(paths))
	results := make(chan error, len(paths))
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for p := range jobs {
			if opts.Progress && !opts.Quiet {
				fmt.Printf("[start] %s\n", p)
			}
			var err error
			if encrypt {
				err = processEncryptFile(p, opts, logf)
			} else {
				err = processDecryptFile(p, opts, logf)
			}
			results <- err
			if opts.Progress && !opts.Quiet {
				fmt.Printf("[done] %s\n", p)
			}
		}
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go worker()
	}
	for _, p := range paths {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(results)
	var firstErr error
	for err := range results {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (o *Options) GetPassword() string {
	if o.UseKeyFile && o.KeyFile != "" {
		b, err := os.ReadFile(o.KeyFile)
		if err != nil {
			fmt.Printf("Warning: failed to read keyfile %s: %v\n", o.KeyFile, err)
			return ""
		}
		return hex.EncodeToString(b)
	}
	return o.Password
}

func interactiveMenu() {
	fmt.Println("===================================")
	fmt.Println(" 🔐 LockBox - Interactive CLI")
	fmt.Println(" Encrypt/decrypt images securely.")
	fmt.Println("===================================")
	fmt.Println("Choose an option:")
	fmt.Println(" 1) Encrypt files")
	fmt.Println(" 2) Decrypt files")
	fmt.Println(" 3) Settings / Defaults")
	fmt.Println(" 4) Help")
	fmt.Println(" 5) Exit")
}

func showHelp() {
	fmt.Println("\n== Help ==")
	fmt.Println("LockBox is a tool to encrypt and decrypt image files securely.")
	fmt.Println("Features:")
	fmt.Println("- Uses AES-GCM encryption with PBKDF2 key derivation.")
	fmt.Println("- Supports compression, secure delete, logging, and more.")
	fmt.Println("- Processes files in parallel for speed.")
	fmt.Println("\nFile Selection:")
	fmt.Println("- Enter paths manually with wildcards (e.g., *.jpg, ~/Desktop/photo.jpg).")
	fmt.Println("- Drag-and-drop files/folders from your file explorer into the terminal.")
	fmt.Println("- Browse directories interactively to select files or folders.")
	fmt.Println("- Quick select Desktop or Pictures directories.")
	fmt.Println("\nOutput Directory Selection:")
	fmt.Println("- Choose to keep the current directory, browse directories, or quick-select Desktop/Pictures.")
	fmt.Println("- Enter paths manually or drag-and-drop for output directory.")
	fmt.Println("\nUsage:")
	fmt.Println("- Select '1' to encrypt: Choose files and output directory via prompts.")
	fmt.Println("- Select '2' to decrypt: Similar to encrypt.")
	fmt.Println("- Select '3' to change default settings.")
	fmt.Println("- Passwords are hidden and confirmed to avoid typos.")
	fmt.Println("- For advanced users: Customize salt, iterations, hash algo.")
	fmt.Println("\nTips:")
	fmt.Println("- Use recursive mode for directories with subfolders.")
	fmt.Println("- Dry-run to test without changes.")
	fmt.Println("- Verbose for detailed output.")
	fmt.Println("\nPress Enter to return to menu.")
	readLine("")
}

func settingsPrompt(opts *Options) {
	fmt.Println("\n== Settings (current values in brackets) ==")
	fmt.Printf("Output directory [%s]: ", opts.OutputDir)
	out, err := selectOutputDir(opts.OutputDir)
	if err != nil {
		fmt.Printf("Error selecting output directory: %v\n", err)
	} else if out != "" {
		opts.OutputDir = out
	}
	fmt.Printf("Suffix for encrypted files [%s]: ", opts.Suffix)
	s := readLine("")
	if s != "" {
		opts.Suffix = s
	}
	fmt.Printf("Parallel workers (0 = auto) [%d]: ", opts.Parallel)
	s = readLine("")
	if s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 {
			opts.Parallel = v
		} else {
			fmt.Println("Invalid number; keeping current.")
		}
	}
	opts.Compress = readYesNo("Use compression by default?", opts.Compress)
	opts.SecureDelete = readYesNo("Use secure-delete by default?", opts.SecureDelete)
	opts.Overwrite = readYesNo("Allow overwrite by default?", opts.Overwrite)
	opts.Recursive = readYesNo("Process directories recursively by default?", opts.Recursive)
	opts.KeepExt = readYesNo("Keep original name for decrypt (no _decrypted added) by default?", opts.KeepExt)
	fmt.Println("Rename pattern example: {name}_locked{ext} (blank to disable)")
	fmt.Printf("Rename pattern [%s]: ", opts.RenamePattern)
	s = readLine("")
	if s != "" {
		opts.RenamePattern = s
	}
	fmt.Println("Include extensions (comma-separated, e.g., jpg,png) - blank for default images")
	s = readLine("Include: ")
	if s != "" {
		parts := strings.Split(s, ",")
		opts.Include = nil
		for _, p := range parts {
			opts.Include = append(opts.Include, normalizeExt(p))
		}
	}
	fmt.Println("Exclude extensions (comma-separated) - blank for none")
	s = readLine("Exclude: ")
	if s != "" {
		parts := strings.Split(s, ",")
		opts.Exclude = nil
		for _, p := range parts {
			opts.Exclude = append(opts.Exclude, normalizeExt(p))
		}
	}
	fmt.Println("Logging file path (blank to disable)")
	fmt.Printf("Log path [%s]: ", opts.LogPath)
	s = readLine("")
	if s != "" {
		opts.LogPath = s
	}
	fmt.Println("Settings updated.")
}

func main() {
	showHelpFlag := flag.Bool("help", false, "show help and exit")
	flag.Parse()
	if *showHelpFlag {
		showHelp()
		return
	}
	opts := &Options{
		Iterations: 100000,
		HashAlgo:   "sha256",
		SaltRandom: true,
		Suffix:     ".enc",
		Parallel:   0, // 0 means auto (NumCPU)
		OutputDir:  ".",
		KeepExt:    true,
	}
	for {
		interactiveMenu()
		choice := readLine("Choice: ")
		switch choice {
		case "1":
			// ENCRYPT flow
			fmt.Println("\n-- Encrypt Files --")
			paths, err := collectPaths()
			if err != nil {
				fmt.Printf("Error selecting paths: %v\n", err)
				continue
			}
			if len(paths) == 0 {
				fmt.Println("No paths selected; returning to menu.")
				continue
			}
			opts.Compress = readYesNo("Compress files before encrypting? (reduces size)", opts.Compress)
			opts.Recursive = readYesNo("Process directories recursively? (include subfolders)", opts.Recursive)
			opts.DryRun = readYesNo("Dry-run? (simulate, no changes made)", opts.DryRun)
			opts.Progress = readYesNo("Show progress for each file?", opts.Progress)
			opts.Verbose = readYesNo("Verbose output? (more details)", opts.Verbose)
			opts.Quiet = false
			opts.Overwrite = readYesNo("Allow overwriting existing output files?", opts.Overwrite)
			opts.RemoveOriginal = readYesNo("Remove original files after encrypting?", opts.RemoveOriginal)
			opts.SecureDelete = readYesNo("Securely delete originals? (overwrite with random data)", opts.SecureDelete)
			p, err := selectOutputDir(opts.OutputDir)
			if err != nil {
				fmt.Printf("Error selecting output directory: %v\n", err)
				continue
			}
			if p != "" {
				opts.OutputDir = p
			}
			fmt.Println("Rename pattern (e.g., {name}_locked{ext}, blank to use default suffix)")
			fmt.Printf("Pattern (current: %s): ", opts.RenamePattern)
			renamePattern := readLine("")
			if renamePattern != "" {
				opts.RenamePattern = renamePattern
			}
			fmt.Println("Include extensions (comma-separated, e.g., jpg,png) - press enter for default image types")
			ii := readLine("Include: ")
			if ii != "" {
				opts.Include = nil
				for _, x := range strings.Split(ii, ",") {
					opts.Include = append(opts.Include, normalizeExt(x))
				}
			}
			fmt.Println("Exclude extensions (comma-separated) - press enter for none")
			excludeExt := readLine("Exclude: ")
			if excludeExt != "" {
				opts.Exclude = nil
				for _, x := range strings.Split(excludeExt, ",") {
					opts.Exclude = append(opts.Exclude, normalizeExt(x))
				}
			}
			fmt.Println("Log file path (press enter to skip)")
			logPath := readLine("Log path: ")
			if logPath != "" {
				opts.LogPath = logPath
			}
			useKey := readYesNo("Use a keyfile instead of password? (keyfile contents used as key)", false)
			if useKey {
				opts.UseKeyFile = true
				opts.KeyFile = readLine("Path to keyfile: ")
				if opts.KeyFile == "" {
					fmt.Println("No keyfile provided; aborting.")
					continue
				}
			} else {
				pw, err := readPasswordWithConfirm("Password: ")
				if err != nil {
					fmt.Printf("Error reading password: %v\n", err)
					continue
				}
				if pw == "" {
					fmt.Println("Empty password not allowed.")
					continue
				}
				opts.Password = pw
				opts.UseKeyFile = false
			}
			if readYesNo("Customize advanced settings (PBKDF2 iterations, salt, hash algo)?", false) {
				fmt.Printf("Iterations (current: %d, recommended 100000+): ", opts.Iterations)
				s := readLine("")
				if s != "" {
					if v, err := strconv.Atoi(s); err == nil && v > 0 {
						opts.Iterations = v
					} else {
						fmt.Println("Invalid number; keeping current.")
					}
				}
				fmt.Println("Salt (hex or text, empty for random)")
				s = readLine("Salt: ")
				if s != "" {
					opts.SaltHex = s
					opts.SaltRandom = false
				}
				fmt.Printf("Hash algo (sha256 or sha512, current: %s): ", opts.HashAlgo)
				s = readLine("")
				if s != "" && (strings.ToLower(s) == "sha256" || strings.ToLower(s) == "sha512") {
					opts.HashAlgo = s
				} else if s != "" {
					fmt.Println("Invalid algo; keeping current.")
				}
			}
			paths, err = walkFiles(paths, opts, true)
			if err != nil {
				fmt.Printf("Error collecting files: %v\n", err)
				continue
			}
			if len(paths) == 0 {
				fmt.Println("No files found to encrypt.")
				continue
			}
			fmt.Printf("Found %d files to encrypt. Proceed?", len(paths))
			if !readYesNo("", true) {
				fmt.Println("Aborted.")
				continue
			}
			start := time.Now()
			if err := runWorkerPool(paths, true, opts); err != nil {
				fmt.Printf("Finished with error: %v\n", err)
			}
			fmt.Printf("Done in %v. Processed %d files.\n\n", time.Since(start), len(paths))
		case "2":
			// DECRYPT flow
			fmt.Println("\n-- Decrypt Files --")
			paths, err := collectPaths()
			if err != nil {
				fmt.Printf("Error selecting paths: %v\n", err)
				continue
			}
			if len(paths) == 0 {
				fmt.Println("No paths selected; returning to menu.")
				continue
			}
			opts.Recursive = readYesNo("Process directories recursively? (include subfolders)", opts.Recursive)
			opts.DryRun = readYesNo("Dry-run? (simulate, no changes made)", opts.DryRun)
			opts.Progress = readYesNo("Show progress for each file?", opts.Progress)
			opts.Verbose = readYesNo("Verbose output? (more details)", opts.Verbose)
			opts.Quiet = false
			opts.Overwrite = readYesNo("Allow overwriting existing output files?", opts.Overwrite)
			opts.RemoveOriginal = readYesNo("Remove original encrypted files after decrypting?", opts.RemoveOriginal)
			opts.SecureDelete = readYesNo("Securely delete originals? (overwrite with random data)", opts.SecureDelete)
			opts.KeepExt = readYesNo("Keep original name (no _decrypted added)?", opts.KeepExt)
			p, err := selectOutputDir(opts.OutputDir)
			if err != nil {
				fmt.Printf("Error selecting output directory: %v\n", err)
				continue
			}
			if p != "" {
				opts.OutputDir = p
			}
			fmt.Println("Rename pattern (e.g., {name}_unlocked{ext}, blank to use default)")
			fmt.Printf("Pattern (current: %s): ", opts.RenamePattern)
			renamePattern := readLine("")
			if renamePattern != "" {
				opts.RenamePattern = renamePattern
			}
			fmt.Println("Include extensions (comma-separated) - press enter for all files")
			ii := readLine("Include: ")
			if ii != "" {
				opts.Include = nil
				for _, x := range strings.Split(ii, ",") {
					opts.Include = append(opts.Include, normalizeExt(x))
				}
			}
			fmt.Println("Exclude extensions (comma-separated) - press enter for none")
			excludeExt := readLine("Exclude: ")
			if excludeExt != "" {
				opts.Exclude = nil
				for _, x := range strings.Split(excludeExt, ",") {
					opts.Exclude = append(opts.Exclude, normalizeExt(x))
				}
			}
			fmt.Println("Log file path (press enter to skip)")
			logPath := readLine("Log path: ")
			if logPath != "" {
				opts.LogPath = logPath
			}
			useKey := readYesNo("Use a keyfile instead of password?", false)
			if useKey {
				opts.UseKeyFile = true
				opts.KeyFile = readLine("Path to keyfile: ")
				if opts.KeyFile == "" {
					fmt.Println("No keyfile provided; aborting.")
					continue
				}
			} else {
				pw, err := readPasswordWithConfirm("Password: ")
				if err != nil {
					fmt.Printf("Error reading password: %v\n", err)
					continue
				}
				if pw == "" {
					fmt.Println("Empty password not allowed.")
					continue
				}
				opts.Password = pw
				opts.UseKeyFile = false
			}
			paths, err = walkFiles(paths, opts, false)
			if err != nil {
				fmt.Printf("Error collecting files: %v\n", err)
				continue
			}
			if len(paths) == 0 {
				fmt.Println("No files found to decrypt.")
				continue
			}
			fmt.Printf("Found %d files to decrypt. Proceed?", len(paths))
			if !readYesNo("", true) {
				fmt.Println("Aborted.")
				continue
			}
			start := time.Now()
			if err := runWorkerPool(paths, false, opts); err != nil {
				fmt.Printf("Finished with error: %v\n", err)
			}
			fmt.Printf("Done in %v. Processed %d files.\n\n", time.Since(start), len(paths))
		case "3":
			settingsPrompt(opts)
		case "4":
			showHelp()
		case "5":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("Invalid choice. Please select 1-5.")
		}
	}
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
