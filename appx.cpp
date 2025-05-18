#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#ifdef max
#undef max // remove max macro windows for use max function of limits.h
#endif

#include <commctrl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <cstdint>
#include <limits>
#include <sstream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <queue>
#include <vector>
#include <opus/opus.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <cassert>
#include <atomic>
#include <wchar.h>

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "libopus.lib")

wchar_t currentDirectory[MAX_PATH];
wchar_t fileIco[] = L"phone_4307.ico";
wchar_t fullPath[MAX_PATH];

// Win32 var
HWND g_main = NULL; //
HINSTANCE g_hInstance;

HWND g_BConnect = NULL; // button
HWND g_BQuit = NULL;
HWND g_BList = NULL;
HWND g_BAccept = NULL;
HWND g_BReject = NULL;

HWND g_Title = NULL;
HWND g_Stats = NULL;
HWND g_IPBox = NULL;
HWND g_StatusBar = NULL;

HFONT hFont = NULL;
HICON hIcon = NULL;

// Socket var
SOCKET serverSocket = INVALID_SOCKET;
SOCKET udpSocket = INVALID_SOCKET;
SOCKET clientSocket = INVALID_SOCKET;
SOCKET acceptSocket = INVALID_SOCKET;
HANDLE stopThreadsEvent = NULL;

WSADATA wsaData;

const int serverPort = 9090;
const int udpPort = 9092;

std::string ipAddress = "";

std::atomic<bool> serverRunning{false};
std::atomic<bool> clientRunning{false};
std::atomic<bool> running{true};

int maxConnections = 1;

// Tcp messages
const char *hello = "VOIP_HELLO\r\n\0";
const char *busy = "VOIP_BUSY\r\n\0";
const char *Vaccept = "VOIP_ACCEPT\r\n\0";
const char *reject = "VOIP_REJECT\r\n\0";
const char *close = "VOIP_CLOSE\r\n\0";
const char *start = "VOIP_START\r\n";
const char *unknown = "Unknown\r\n\0";

// Audio var
struct AudioBuffer
{
    BYTE *data;
    UINT32 frames;
    UINT32 size;
};

// audio queue and mutex
std::queue<AudioBuffer> captureQueue;
std::queue<std::vector<unsigned char>> encodeQueue;
std::queue<std::vector<unsigned char>> decodeQueue;
std::queue<AudioBuffer> playbackQueue;

std::mutex captureMutex;
std::mutex encodeMutex;
std::mutex decodeMutex;
std::mutex playbackMutex;
std::mutex peersMutex;

// Threads var
std::thread captureThread;
std::thread encodeThread;
std::thread decodeThread;
std::thread playbackThread;
std::thread serverListenerThread;
std::thread serverHandleConnectionThread;
std::thread clientListenerThread;
std::thread udpListenerThread;
std::thread statsThread;

// Peers management
struct Peer
{
    std::string addr;
    std::string name;
    time_t lastActivity;
    bool active;
    time_t connectionStartTime;
    time_t totalActiveTime;
    uint64_t totalBytesReceived = 0;
    uint64_t totalBytesSent = 0;
    Peer() : lastActivity(0), active(false), connectionStartTime(0),
             totalActiveTime(0), totalBytesReceived(0), totalBytesSent(0) {}
};

Peer peer = Peer();

// Controller ID
#define ID_BUTTON_CONNECT 101
#define ID_BUTTON_QUIT 102
#define ID_BUTTON_LIST 103
#define ID_BUTTON_ACCEPT 104
#define ID_BUTTON_REJECT 105
#define ID_STATS 110
#define ID_IPBOX 111
#define ID_STATUSBAR 112
#define ID_STATIC_TITLE 113

// Personal messages for win32
#define WM_UPDATE_TITLE (WM_USER + 2)
#define WM_CONNECTING (WM_USER + 3)
#define WM_INCOMING (WM_USER + 4)
#define WM_CONNECTED (WM_USER + 5)
#define WM_BUSY (WM_USER + 6)
#define WM_ACCEPT (WM_USER + 7)
#define WM_REJECT (WM_USER + 8)
#define WM_CALL_ENDING (WM_USER + 9)
#define WM_CALL_END (WM_USER + 10)
#define WM_OFFLINE (WM_USER + 11)
#define WM_RESET (WM_USER + 12)

// Audio Configuration
#define SAMPLE_RATE 48000
#define CHANNELS 2
#define FRAME_SIZE 960       // 20ms at 48KHz
#define MAX_PACKET_SIZE 1500 // Max compressed size per documentation
#define BUFFER_SIZE 4800     // 100ms buffer

// Functions
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow); // main Windows function
LRESULT CALLBACK WindowProc(HWND g_main, UINT uMsg, WPARAM wParam, LPARAM lParam);               // callback loop messages

void initSocket(SOCKET &mysocket, IPPROTO protocol, int port); // initialize socket udp or tcp, if tcp initialize server socket
void cleanupSocket(SOCKET &socket);                            // close socket

void changeStatus(const std::string &first, const std::string &second, bool reset); // change status bar text
void changeTitle(HWND control, LPCWSTR newTitle, bool timer);                       // change  title text

void getIpAddress();                                 // get ip string  from win32 control
const char *addComputerName(const char *firstHalf);  // add computer name in message to send in tcp connection
std::string extractComputerName(std::string buffer); // extract computer name from message from tcp connection
void restartThreadsIfNeeded();                       // restart audio threads

void captureAudio();  // capture audio with COM
void encodeAudio();   // encode audio data with opus
void decodeAudio();   // decode audio data with opus
void playbackAudio(); // play audio with COM
void statsMonitor();  // stats of call in progress

void udpConnecting();                                                       // udp socket is for transfer audio data
void udpListener();                                                         // listener for udp socket
void tcpConnecting();                                                       // tcp socket is for handle call and create clientSocket
void serverListener();                                                      // listener for incoming call
void serverHandleConnection();                                              // handle accept socket in tcp socket, num accept socket = 1
void clientListener();                                                      // handle for clientSocket
void tcpSender(SOCKET socket, const char *message, std::atomic<bool> &run); // for sending message in tcp connection

// Initialize COM for audio
class ComInitializer
{
public:
    ComInitializer()
    {
        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        assert(SUCCEEDED(hr));
    }
    ~ComInitializer()
    {
        CoUninitialize();
    }
};

void initSocket(SOCKET &mysocket, IPPROTO protocol, int port)
{

    if (protocol == IPPROTO_UDP)
    {
        mysocket = socket(AF_INET, SOCK_DGRAM, protocol);
        if (mysocket == INVALID_SOCKET)
        {
            changeStatus("Udp Socket creation failed:", std::to_string(WSAGetLastError()), true);
            return;
        }

        // Enable broadcast
        bool broadcast = true;
        if (setsockopt(mysocket, SOL_SOCKET, SO_BROADCAST, (char *)&broadcast, sizeof(broadcast)) == SOCKET_ERROR)
        {
            changeStatus("Broadcast Udp Socket failed:", std::to_string(WSAGetLastError()), true);
            return;
        }

        // Bind socket to local port
        sockaddr_in localAddr;
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = htons(port);

        if (bind(mysocket, reinterpret_cast<struct sockaddr *>(&localAddr), sizeof(localAddr)) == SOCKET_ERROR)
        {
            changeStatus("Bind Udp Socket failed:", std::to_string(WSAGetLastError()), true);
        }

        else
        {
            changeStatus("VOIP P2P started, listening on port: ", std::to_string(port), false);
        }
    }

    if (protocol == IPPROTO_TCP)
    {
        mysocket = socket(AF_INET, SOCK_STREAM, protocol);
        if (mysocket == INVALID_SOCKET)
        {
            changeStatus("Tcp Socket creation failed: ", std::to_string(WSAGetLastError()), true);
            return;
        }

        u_long mode = 1; // not blocking mode
        if (ioctlsocket(mysocket, FIONBIO, &mode) != NO_ERROR)
        {
            changeStatus("Tcp Socket not blocking failed: ", std::to_string(WSAGetLastError()), true);
            return;
        }

        int keepAlive = 1; // Abilita Keep-Alive
        if (setsockopt(mysocket, SOL_SOCKET, SO_KEEPALIVE, (char *)&keepAlive, sizeof(keepAlive)) == SOCKET_ERROR)
        {
            changeStatus("Tcp Socket Keep-Alive failed: ", std::to_string(WSAGetLastError()), true);
            return;
        }

        // server address
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY; // any address aviable
        serverAddr.sin_port = htons(port);

        // bind
        if (bind(mysocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
        {
            changeStatus("Bind Tcp Socket creation failed: ", std::to_string(WSAGetLastError()), true);
            return;
        }

        if (listen(mysocket, maxConnections) == SOCKET_ERROR)
        {
            changeStatus("Tcp Socket listening failed: ", std::to_string(WSAGetLastError()), true);
            return;
        }

        serverRunning = true;
        // start thread for incoming connection
        serverListenerThread = std::thread(serverListener);
        serverListenerThread.detach();
    }
}

void cleanupSocket(SOCKET &socket)
{
    if (socket != INVALID_SOCKET)
    {
        // notify to thread that socket is ongoing close
        SOCKET tempSocket = socket;
        socket = INVALID_SOCKET;

        // close socket
        shutdown(tempSocket, SD_BOTH);

        if (closesocket(tempSocket) == SOCKET_ERROR)
        {
            DWORD error = WSAGetLastError();
            // ignore invalid socket error
            if (error != WSAENOTSOCK)
            {
                changeStatus("Error closing socket", std::to_string(error), false);
            }
        }
    }
}

void changeStatus(const std::string &first, const std::string &second, bool reset)

{
    std::wstring wStatusText = std::wstring(first.begin(), first.end()) + std::wstring(second.begin(), second.end());
    SendMessageTimeout(g_StatusBar, WM_SETTEXT, 0, (LPARAM)wStatusText.c_str(), SMTO_ABORTIFHUNG, 500, NULL);

    if (reset)
    {
        Sleep(5000);
        PostMessage(g_main, WM_RESET, 0, 0);
    }
}

void changeTitle(HWND control, LPCWSTR newTitle, bool timer)
{
    if (timer)
    {
        SetWindowText(control, newTitle);
        std::thread([hwnd = g_main]()
                    { std::this_thread::sleep_for(std::chrono::seconds(5)); })
            .detach();
    }
    else
    {
        SetWindowText(control, newTitle);
    }
}

void getIpAddress()
{
    DWORD dwAddress = 0;
    if (SendMessage(g_IPBox, IPM_GETADDRESS, 0, (LPARAM)&dwAddress) == 0)
    {
        // No ip
        changeStatus("Invalid Ip", "", false);
        return;
    }

    // Extract octet
    BYTE octet1 = FIRST_IPADDRESS(dwAddress);
    BYTE octet2 = SECOND_IPADDRESS(dwAddress);
    BYTE octet3 = THIRD_IPADDRESS(dwAddress);
    BYTE octet4 = FOURTH_IPADDRESS(dwAddress);

    // convert octets in a string
    std::ostringstream ipStream;
    ipStream << (int)octet1 << "."
             << (int)octet2 << "."
             << (int)octet3 << "."
             << (int)octet4;

    ipAddress = ipStream.str();
}

const char *addComputerName(const char *firstHalf)
{

    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    char *computerNamePointer = nullptr;

    if (GetComputerNameA(computerName, &size))
    {
        computerNamePointer = computerName;
    }
    else
    {
        computerNamePointer = const_cast<char *>(unknown);
    }
    // Alloca memoria per il messaggio
    char *message = new char[256];
    memset(message, 0, 256); // Inizializza a zero

    // Componi il messaggio
    strncpy(message, firstHalf, 255);
    strncat(message, "\n", 255 - strlen(message));                // Aggiungi il newline
    strncat(message, computerNamePointer, 255 - strlen(message)); // Aggiungi il computerName

    return message;
}

std::string extractComputerName(std::string buffer)
{
    std::string delimiter = "\r\n";
    size_t pos = buffer.find(delimiter);
    if (pos != std::string::npos)
    {
        std::string result = buffer.substr(pos + 2);
        return result;
    }

    else
    {
        return unknown;
    }
}

void restartThreadsIfNeeded()
{
    // For each thread, check if it's not running and restart it

    if (!captureThread.joinable())
    {
        try
        {
            captureThread = std::thread(captureAudio);
            captureThread.detach(); // Detach immediately to prevent join issues
        }
        catch (const std::system_error &e)
        {
            changeStatus("Failed to start capture thread: ", std::string(e.what()), false);
        }
    }

    if (!encodeThread.joinable())
    {
        try
        {
            encodeThread = std::thread(encodeAudio);
            encodeThread.detach();
        }
        catch (const std::system_error &e)
        {
            changeStatus("Failed to start encode thread: ", std::string(e.what()), false);
        }
    }

    if (!udpListenerThread.joinable())
    {
        try
        {
            udpListenerThread = std::thread(udpListener);
            udpListenerThread.detach();
        }
        catch (const std::system_error &e)
        {
            changeStatus("Failed to start Udp listener thread: ", std::string(e.what()), false);
        }
    }

    if (!decodeThread.joinable())
    {
        try
        {
            decodeThread = std::thread(decodeAudio);
            decodeThread.detach();
        }
        catch (const std::system_error &e)
        {
            changeStatus("Failed to start decode thread: ", std::string(e.what()), false);
        }
    }

    if (!playbackThread.joinable())
    {
        try
        {
            playbackThread = std::thread(playbackAudio);
            playbackThread.detach();
        }
        catch (const std::system_error &e)
        {
            changeStatus("Failed to start playback thread: ", std::string(e.what()), false);
        }
    }

    if (!statsThread.joinable())
    {
        try
        {
            statsThread = std::thread(statsMonitor);
            statsThread.detach();
        }
        catch (const std::system_error &e)
        {
            changeStatus("Failed to start stats thread: ", std::string(e.what()), false);
        }
    }
}

void tcpConnecting()
{
    getIpAddress();

    // Update status
    changeStatus("Connection to ", ipAddress, false);

    {
        std::lock_guard<std::mutex> lock(peersMutex);
        peer.addr = ipAddress;
        peer.active = false;
    }

    // Create Peer Ip Address
    sockaddr_in peerAddr;
    memset(&peerAddr, 0, sizeof(peerAddr)); // initialize to 0

    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(serverPort);

    // Check if Ip Address is valid
    if (inet_pton(AF_INET, ipAddress.c_str(), &peerAddr.sin_addr) != 1)

    {
        changeStatus("Invalid Ip Address", "", true);
        return;
    }

    // new socket

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (clientSocket == INVALID_SOCKET)
    {
        changeStatus("Error creating socket", std::to_string(WSAGetLastError()), true);
        return;
    }

    u_long mode = 1; // not blocking mode
    if (ioctlsocket(clientSocket, FIONBIO, &mode) != NO_ERROR)
    {
        changeStatus("Tcp Socket not blocking failed:", std::to_string(WSAGetLastError()), true);
        return;
    }
    // Timeout
    DWORD timeout = 5000;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    // new peer socket and connection

    int result = connect(clientSocket, (struct sockaddr *)&peerAddr, sizeof(peerAddr));

    if (result == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)
    {

        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(clientSocket, &writeSet);

        timeval timeout;
        timeout.tv_sec = 5; // Timeout 5 secs
        timeout.tv_usec = 0;

        result = select(clientSocket + 1, nullptr, &writeSet, nullptr, &timeout);

        if (result > 0 && FD_ISSET(clientSocket, &writeSet))

        {
            // Check status connection
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(clientSocket, SOL_SOCKET, SO_ERROR, (char *)&error, &len);
            if (error == 0)
            {
                clientRunning = true;
                // Starts thread for incoming connections only if socket is valid
                clientListenerThread = std::thread(clientListener);
                clientListenerThread.detach();
                return;
            }
            else
            {
                changeStatus("Error connecting: ", ipAddress, true);
            }
        }
        else
        {
            changeStatus("Timeout connecting", "", false);
            PostMessage(g_main, WM_OFFLINE, 0, NULL);
        }
    }
    else
    {
        changeStatus("Connection failed immediately: ", std::to_string(WSAGetLastError()), true);
    }
}

void udpConnecting()
{
    // Create Ip Address peer
    sockaddr_in peerAddr;
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(udpPort);
    inet_pton(AF_INET, peer.addr.c_str(), &peerAddr.sin_addr);

    const int maxRetries = 5;      // max
    const int retryDelayMs = 1000; // delay

    if (udpSocket != INVALID_SOCKET)
    {
        int attempt = 0;
        while (attempt < maxRetries)
        {
            int sentBytes = sendto(udpSocket, start, strlen(start), 0,
                                   (struct sockaddr *)&peerAddr, sizeof(peerAddr));

            if (sentBytes != -1) // if success loop exit
            {
                changeStatus("Connected with: ", peer.addr, false);

                {
                    std::lock_guard<std::mutex> lock(peersMutex);

                    // is a new connection ?
                    bool isNewConnection = !peer.active;

                    // update last activty
                    peer.lastActivity = time(nullptr);
                    peer.active = true;

                    // only if is a new connection, initialize time
                    if (isNewConnection)
                    {
                        peer.connectionStartTime = time(nullptr);
                        peer.totalActiveTime = 0;
                    }
                    // else
                }

                SendMessage(g_main, WM_CONNECTED, 0, 0);
                break; // exit loop, connection established
            }
            else
            {
                changeStatus("Retrying connection with: ", peer.addr, false);
                std::this_thread::sleep_for(std::chrono::milliseconds(retryDelayMs));
                attempt++;
            }
        }

        if (attempt == maxRetries) // if all retrys fall
        {
            changeStatus("Failed to connect with: ", peer.addr, true);
        }
    }
}

void captureAudio()
{
    ComInitializer comInit;
    IMMDeviceEnumerator *pEnumerator = nullptr;
    IMMDevice *pDevice = nullptr;
    IAudioClient *pAudioClient = nullptr;
    IAudioCaptureClient *pCaptureClient = nullptr;
    WAVEFORMATEX *pCaptureFormat = nullptr;

    try
    {
        // Get audio device
        HRESULT hr = CoCreateInstance(
            __uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
            __uuidof(IMMDeviceEnumerator), (void **)&pEnumerator);
        if (FAILED(hr))
            throw std::runtime_error("Failed to create device enumerator");

        hr = pEnumerator->GetDefaultAudioEndpoint(eCapture, eCommunications, &pDevice);
        if (FAILED(hr))
            throw std::runtime_error("Failed to get default audio endpoint");

        hr = pDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL,
                               nullptr, (void **)&pAudioClient);
        if (FAILED(hr))
            throw std::runtime_error("Failed to activate audio client");

        // Create and set desired format instead of using the mix format
        pCaptureFormat = static_cast<WAVEFORMATEX *>(CoTaskMemAlloc(sizeof(WAVEFORMATEX)));
        if (!pCaptureFormat)
            throw std::runtime_error("Failed to allocate memory for wave format");

        // Set up PCM format with 16-bit samples
        pCaptureFormat->wFormatTag = WAVE_FORMAT_PCM;
        pCaptureFormat->nChannels = CHANNELS;
        pCaptureFormat->nSamplesPerSec = SAMPLE_RATE;
        pCaptureFormat->wBitsPerSample = 16;
        pCaptureFormat->nBlockAlign = (pCaptureFormat->nChannels * pCaptureFormat->wBitsPerSample) / 8;
        pCaptureFormat->nAvgBytesPerSec = pCaptureFormat->nSamplesPerSec * pCaptureFormat->nBlockAlign;
        pCaptureFormat->cbSize = 0;

        // Check if format is supported
        WAVEFORMATEX *pClosestMatch = nullptr;
        hr = pAudioClient->IsFormatSupported(AUDCLNT_SHAREMODE_SHARED, pCaptureFormat, &pClosestMatch);

        if (hr == S_FALSE && pClosestMatch)
        {
            changeStatus("Using closest matching format instead of requested format", "", false);

            CoTaskMemFree(pCaptureFormat);
            pCaptureFormat = pClosestMatch;
        }
        else if (FAILED(hr))
        {
            CoTaskMemFree(pCaptureFormat);
            throw std::runtime_error("Requested audio format is not supported");
        }

        // Configure audio client with the format
        hr = pAudioClient->Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            0,
            10000000, // 1 second buffer
            0,
            pCaptureFormat,
            nullptr);
        if (FAILED(hr))
            throw std::runtime_error("Failed to initialize audio client");

        hr = pAudioClient->GetService(__uuidof(IAudioCaptureClient),
                                      (void **)&pCaptureClient);
        if (FAILED(hr))
            throw std::runtime_error("Failed to get capture client");

        hr = pAudioClient->Start();
        if (FAILED(hr))
            throw std::runtime_error("Failed to start audio client");

        // Capture loop
        while (running)
        {
            UINT32 packetSize = 0;
            BYTE *pData;
            DWORD flags;
            UINT32 numFramesAvailable;

            hr = pCaptureClient->GetNextPacketSize(&packetSize);
            if (FAILED(hr))
                throw std::runtime_error("Failed to get next packet size");

            while (packetSize > 0)
            {
                hr = pCaptureClient->GetBuffer(&pData, &numFramesAvailable, &flags, nullptr, nullptr);
                if (FAILED(hr))
                    throw std::runtime_error("Failed to get buffer");

                // Convert to float and push to queue
                if (numFramesAvailable > 0)
                {
                    // calculate the size of the captured data
                    UINT32 dataSize = numFramesAvailable * pCaptureFormat->nBlockAlign;
                    // create a new audio buffer
                    AudioBuffer buffer;
                    buffer.data = new BYTE[dataSize];
                    buffer.frames = numFramesAvailable;
                    buffer.size = dataSize;
                    // paste data in the buffer and handle silent flag
                    if (flags & AUDCLNT_BUFFERFLAGS_SILENT)
                    {
                        memset(buffer.data, 0, dataSize);
                    }
                    else
                    {
                        memcpy(buffer.data, pData, dataSize);
                    }

                    // push buffer in the queue
                    {
                        std::lock_guard<std::mutex> lock(captureMutex);
                        captureQueue.push(buffer);
                    }
                }

                hr = pCaptureClient->ReleaseBuffer(numFramesAvailable);
                if (FAILED(hr))
                    throw std::runtime_error("Failed to release buffer");

                hr = pCaptureClient->GetNextPacketSize(&packetSize);
                if (FAILED(hr))
                    throw std::runtime_error("Failed to get next packet size");
            }

            // Sleep to prevent tight loop
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    catch (const std::exception &e)
    {
        changeStatus("Capture thread error: ", std::string(e.what()), false);
    }

    // Cleanup
    if (pAudioClient)
        pAudioClient->Stop();
    if (pCaptureFormat)
        CoTaskMemFree(pCaptureFormat);
    if (pCaptureClient)
        pCaptureClient->Release();
    if (pAudioClient)
        pAudioClient->Release();
    if (pDevice)
        pDevice->Release();
    if (pEnumerator)
        pEnumerator->Release();
}

void encodeAudio()
{
    // Initialize Opus encoder
    int error;
    OpusEncoder *encoder = opus_encoder_create(SAMPLE_RATE, CHANNELS, OPUS_APPLICATION_VOIP, &error);
    if (error != OPUS_OK)
    {
        changeStatus("Failed to create encoder: ", std::string(opus_strerror(error)), false);
        return;
    }

    // Configure Opus encoder settings
    opus_encoder_ctl(encoder, OPUS_SET_BITRATE(SAMPLE_RATE)); // Set bitrate to 96 kbps
    opus_encoder_ctl(encoder, OPUS_SET_COMPLEXITY(8));        // Set complexity level
    opus_encoder_ctl(encoder, OPUS_SET_BANDWIDTH(OPUS_BANDWIDTH_NARROWBAND));
    opus_encoder_ctl(encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE)); // Optimize for voice
    opus_encoder_ctl(encoder, OPUS_SET_DTX(0));                    // Enable discontinuous transmission
    opus_encoder_ctl(encoder, OPUS_SET_GAIN(0));                   // Adjust gain if needed

    // Buffer for encoded audio data
    unsigned char encodedData[MAX_PACKET_SIZE];

    while (running)
    {
        AudioBuffer buffer;
        bool hasBuffer = false;

        // Retrieve buffer from queue
        {
            std::unique_lock<std::mutex> lock(captureMutex);
            if (!captureQueue.empty())
            {
                buffer = captureQueue.front();
                captureQueue.pop();
                hasBuffer = true;
            }
        }

        if (hasBuffer)
        {
            // Encode the buffer using Opus
            int bytesEncoded = opus_encode(encoder,
                                           reinterpret_cast<const opus_int16 *>(buffer.data),
                                           buffer.frames,
                                           encodedData,
                                           MAX_PACKET_SIZE);

            if (bytesEncoded > 0)
            {
                // Push encoded data to queue
                {
                    std::lock_guard<std::mutex> lock(encodeMutex);
                    encodeQueue.push(std::vector<unsigned char>(encodedData, encodedData + bytesEncoded));
                }

                // Send encoded data to active peers
                if (udpSocket != INVALID_SOCKET)
                {
                    std::lock_guard<std::mutex> lock(peersMutex);

                    if (peer.active)
                    {

                        sockaddr_in addr;
                        addr.sin_family = AF_INET;
                        addr.sin_port = htons(udpPort); // Porta standard
                        inet_pton(AF_INET, peer.addr.c_str(), &addr.sin_addr);
                        int bytesSent = sendto(udpSocket,
                                               reinterpret_cast<const char *>(encodedData),
                                               bytesEncoded,
                                               0,
                                               reinterpret_cast<struct sockaddr *>(&addr),
                                               sizeof(addr));

                        if (bytesSent > 0)
                        {
                            if (std::numeric_limits<uint64_t>::max() - peer.totalBytesSent >= static_cast<uint64_t>(bytesSent))
                            {
                                // Safe to add - no overflow will occur
                                peer.totalBytesSent += static_cast<uint64_t>(bytesSent);
                            }
                            else
                            {
                                // Handle potential overflow - cap at max
                                peer.totalBytesSent = std::numeric_limits<uint64_t>::max();

                                // Optionally log the overflow
                                changeStatus("Sent bytes counter reached maximum value.", "", false);
                            }
                        }
                        else
                        {
                            changeStatus("Error sending audio data:", std::to_string(WSAGetLastError()), false);
                        }
                    }
                }
            }
            else
            {
                changeStatus("Encoding failed:", std::string(opus_strerror(bytesEncoded)), false);
            }

            // Clean up buffer memory
            delete[] buffer.data;
        }
    }

    // Cleanup
    opus_encoder_destroy(encoder);
}

void decodeAudio()
{
    // Initialize Opus decoder
    int error;
    OpusDecoder *decoder = opus_decoder_create(SAMPLE_RATE, CHANNELS, &error);
    if (error != OPUS_OK)
    {
        changeStatus("Failed to create decoder: ", std::string(opus_strerror(error)), false);
        return;
    }

    // Buffer for data
    BYTE receivedData[MAX_PACKET_SIZE];
    std::vector<opus_int16> decodedData(FRAME_SIZE * CHANNELS); // automatic allocation with std::vector

    while (running)
    {
        std::vector<unsigned char> packetToDecode;
        {
            std::lock_guard<std::mutex> lock(decodeMutex);
            if (!decodeQueue.empty())
            {
                packetToDecode = std::move(decodeQueue.front());
                decodeQueue.pop();
            }
        }

        if (!packetToDecode.empty())
        {
            int samplesDecoded = opus_decode(decoder, packetToDecode.data(), packetToDecode.size(),
                                             decodedData.data(), FRAME_SIZE, 0);

            if (samplesDecoded > 0)
            {
                UINT32 dataSize = samplesDecoded * CHANNELS * sizeof(short);

                AudioBuffer buffer;
                buffer.data = new BYTE[dataSize]; // dinamic allocation
                buffer.frames = samplesDecoded;
                buffer.size = dataSize;

                memcpy(buffer.data, decodedData.data(), dataSize);

                // put buffer in the queue
                {
                    std::lock_guard<std::mutex> lock(playbackMutex);
                    playbackQueue.push(buffer);
                }
            }
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Cleanup
    opus_decoder_destroy(decoder);
}

void playbackAudio()
{
    ComInitializer comInit;
    IMMDeviceEnumerator *pEnumerator = nullptr;
    IMMDevice *pDevice = nullptr;
    IAudioClient *pAudioClient = nullptr;
    IAudioRenderClient *pRenderClient = nullptr;
    WAVEFORMATEX *pRenderFormat = nullptr;

    try
    {
        // Initialize audio device
        HRESULT hr = CoCreateInstance(
            __uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
            __uuidof(IMMDeviceEnumerator), reinterpret_cast<void **>(&pEnumerator));
        if (FAILED(hr))
            throw std::runtime_error("Failed to create device enumerator");

        hr = pEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &pDevice);
        if (FAILED(hr))
            throw std::runtime_error("Failed to get default audio endpoint");

        hr = pDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, reinterpret_cast<void **>(&pAudioClient));
        if (FAILED(hr))
            throw std::runtime_error("Failed to activate audio client");

        // Allocate and set up PCM format
        pRenderFormat = static_cast<WAVEFORMATEX *>(CoTaskMemAlloc(sizeof(WAVEFORMATEX)));
        if (!pRenderFormat)
            throw std::runtime_error("Failed to allocate memory for wave format");

        pRenderFormat->wFormatTag = WAVE_FORMAT_PCM;
        pRenderFormat->nChannels = CHANNELS;
        pRenderFormat->nSamplesPerSec = SAMPLE_RATE;
        pRenderFormat->wBitsPerSample = 16;
        pRenderFormat->nBlockAlign = (pRenderFormat->nChannels * pRenderFormat->wBitsPerSample) / 8;
        pRenderFormat->nAvgBytesPerSec = pRenderFormat->nSamplesPerSec * pRenderFormat->nBlockAlign;
        pRenderFormat->cbSize = 0;

        WAVEFORMATEX *pClosestMatch = nullptr;
        hr = pAudioClient->IsFormatSupported(AUDCLNT_SHAREMODE_SHARED, pRenderFormat, &pClosestMatch);

        if (hr == S_FALSE && pClosestMatch)
        {
            changeStatus("Closest matching format will be used.", "", false);
            CoTaskMemFree(pRenderFormat);
            pRenderFormat = pClosestMatch;
        }
        else if (FAILED(hr))
        {
            CoTaskMemFree(pRenderFormat);
            throw std::runtime_error("Requested audio format not supported");
        }

        hr = pAudioClient->Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            0,
            10000000, // 1-second buffer
            0,
            pRenderFormat,
            nullptr);
        if (FAILED(hr))
            throw std::runtime_error("Failed to initialize audio client");

        hr = pAudioClient->GetService(__uuidof(IAudioRenderClient), reinterpret_cast<void **>(&pRenderClient));
        if (FAILED(hr))
            throw std::runtime_error("Failed to get render client");

        UINT32 bufferFrameCount;
        hr = pAudioClient->GetBufferSize(&bufferFrameCount);
        if (FAILED(hr))
            throw std::runtime_error("Failed to get buffer size");

        hr = pAudioClient->Start();
        if (FAILED(hr))
            throw std::runtime_error("Failed to start audio client");

        // Playback loop
        while (running)
        {
            UINT32 numFramesPadding = 0;
            hr = pAudioClient->GetCurrentPadding(&numFramesPadding);
            if (FAILED(hr))
                throw std::runtime_error("Failed to get current padding");

            UINT32 numFramesAvailable = bufferFrameCount - numFramesPadding;

            if (numFramesAvailable > 0)
            {
                AudioBuffer buffer;
                bool hasBuffer = false;

                // Fetch a buffer from playback queue
                {
                    std::unique_lock<std::mutex> lock(playbackMutex);
                    if (!playbackQueue.empty())
                    {
                        buffer = playbackQueue.front();
                        playbackQueue.pop();
                        hasBuffer = true;
                    }
                    else
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                        continue;
                    }
                }

                if (hasBuffer)
                {
                    UINT32 framesToWrite = min(numFramesAvailable, buffer.frames);
                    BYTE *pData = nullptr;

                    hr = pRenderClient->GetBuffer(framesToWrite, &pData);
                    if (FAILED(hr))
                        throw std::runtime_error("Failed to get render buffer");

                    memcpy(pData, buffer.data, framesToWrite * pRenderFormat->nBlockAlign);

                    hr = pRenderClient->ReleaseBuffer(framesToWrite, 0);
                    if (FAILED(hr))
                        throw std::runtime_error("Failed to release render buffer");

                    delete[] buffer.data; // Free memory after use
                }
            }
            else
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
    catch (const std::exception &e)
    {
        changeStatus("Playback error: ", std::string(e.what()), false);
    }

    // Cleanup
    if (pAudioClient)
        pAudioClient->Stop();
    if (pRenderClient)
        pRenderClient->Release();
    if (pAudioClient)
        pAudioClient->Release();
    if (pDevice)
        pDevice->Release();
    if (pEnumerator)
        pEnumerator->Release();
    if (pRenderFormat)
        CoTaskMemFree(pRenderFormat);
}

void serverListener()
{

    fd_set readfds;

    while (true)
    {
        if (WaitForSingleObject(stopThreadsEvent, 0) == WAIT_OBJECT_0)
        {
            break;
        }
        while (serverRunning && serverSocket != INVALID_SOCKET)
        {

            FD_ZERO(&readfds);
            FD_SET(serverSocket, &readfds);

            // wait a connection
            int activity = select(static_cast<int>(serverSocket + 1), &readfds, nullptr, nullptr, nullptr);

            if (activity < 0 && WSAGetLastError() != WSAEINTR)
            {
                changeStatus("Select error in server socket: ", std::to_string(WSAGetLastError()), true);
                break;
            }

            // Check socket server has an incoming connection
            if (FD_ISSET(serverSocket, &readfds))
            {
                SOCKET newSocket = accept(serverSocket, nullptr, nullptr);

                if (newSocket == INVALID_SOCKET)
                {
                    int error = WSAGetLastError();
                    changeStatus("Accept socket error: ", std::to_string(error), true);
                    continue;
                }

                u_long mode = 1;
                ioctlsocket(newSocket, FIONBIO, &mode);

                if (acceptSocket == INVALID_SOCKET)
                {
                    // no active client, accept connection
                    acceptSocket = newSocket;

                    // get ip
                    sockaddr_in clientAddr;
                    socklen_t addrLen = sizeof(clientAddr);
                    getpeername(acceptSocket, (struct sockaddr *)&clientAddr, &addrLen);
                    char clientIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);

                    {
                        std::lock_guard<std::mutex> peerLock(peersMutex);
                        peer.addr = clientIP;
                        peer.active = true;
                        peer.connectionStartTime = time(nullptr);
                        peer.totalActiveTime = 0;
                    }

                    // handle connection
                    serverHandleConnectionThread = std::thread(serverHandleConnection);
                    serverHandleConnectionThread.detach();
                }
                else
                {
                    // server busy, send message
                    send(newSocket, busy, strlen(busy), 0);
                    closesocket(newSocket);
                }
            }

            // check if active client has close connection

            if (acceptSocket != INVALID_SOCKET)
            {
                char buffer[1];
                int recvResult = recv(acceptSocket, buffer, sizeof(buffer), MSG_PEEK);

                if (recvResult == 0 || (recvResult == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK))
                {
                    closesocket(acceptSocket);
                    acceptSocket = INVALID_SOCKET;
                }
            }
        }
    }
}

void serverHandleConnection()
{
    char buffer[1024] = {0};
    std::string dataBuffer;

    while (true)
    {
        if (WaitForSingleObject(stopThreadsEvent, 0) == WAIT_OBJECT_0)
        {
            break;
        }
        while (serverRunning && acceptSocket != INVALID_SOCKET)
        {

            int bytesReceived = recv(acceptSocket, buffer, sizeof(buffer) - 1, 0);

            if (bytesReceived == 0)
            {
                // Connection close from client
                SendMessage(g_main, WM_CALL_END, 0, 0);

                cleanupSocket(acceptSocket);

                break;
            }
            else if (bytesReceived > 0)
            {

                buffer[bytesReceived] = '\0';
                dataBuffer.append(buffer, bytesReceived);

                if (strncmp(dataBuffer.c_str(), hello, strlen(hello)) == 0)
                {
                    // handshake message with computer name
                    {
                        std::lock_guard<std::mutex> lock(peersMutex);
                        peer.name = extractComputerName(dataBuffer);
                    }
                    SendMessage(g_main, WM_INCOMING, 0, 0);
                    dataBuffer.clear();
                }
                else if (dataBuffer.find(close) != std::string::npos)
                {
                    // close message
                    SendMessage(g_main, WM_CALL_END, 0, 0);
                    cleanupSocket(acceptSocket);
                    return;
                }
            }
            else
            {
                // error o no data available
                int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK)
                {
                    Sleep(10);
                }
                else
                {
                    // comunication error
                    changeStatus("Tcp Socket receiving error: ", std::to_string(error), false);
                    cleanupSocket(acceptSocket);
                    break;
                }
            }
        }
    }
}

void clientListener()
{

    char buffer[1024] = {0};
    std::string dataBuffer;

    while (true)
    {
        if (WaitForSingleObject(stopThreadsEvent, 0) == WAIT_OBJECT_0)
        {
            break;
        }
        while (clientRunning && clientSocket != INVALID_SOCKET)

        {

            int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

            if (bytesReceived > 0)
            {
                buffer[bytesReceived] = '\0';
                dataBuffer.append(buffer, bytesReceived);

                if (dataBuffer.find(Vaccept) != std::string::npos)
                {
                    changeStatus("Connected with: ", peer.addr, false);
                    SendMessage(g_main, WM_ACCEPT, 0, NULL);

                    {
                        std::lock_guard<std::mutex> lock(peersMutex);

                        peer.name = extractComputerName(dataBuffer);

                        peer.active = true;
                    }
                    dataBuffer.erase(0, dataBuffer.find(Vaccept) + strlen(Vaccept));
                }
                else if (dataBuffer.find(reject) != std::string::npos)
                {
                    changeStatus("Connection rejected from: ", peer.addr, false);

                    dataBuffer.erase(0, dataBuffer.find(reject) + strlen(reject));
                    SendMessage(g_main, WM_REJECT, 0, NULL);
                }

                else if (dataBuffer.find(close) != std::string::npos)
                {
                    dataBuffer.erase(0, dataBuffer.find(close) + strlen(close));
                    SendMessage(g_main, WM_CALL_END, 0, NULL);
                }
                else if (dataBuffer.find(busy) != std::string::npos)
                {
                    changeStatus("Busy peer: ", peer.addr, false);
                    dataBuffer.erase(0, dataBuffer.find(busy) + strlen(busy));
                    PostMessage(g_main, WM_BUSY, 0, NULL);
                }
            }

            else
            {
                // error
                int error = WSAGetLastError();

                if (error == WSAETIMEDOUT)
                {
                    changeStatus("Timeout connection with: ", ipAddress, false);
                    PostMessage(g_main, WM_OFFLINE, 0, NULL);
                    break;
                }

                if (error == WSAEWOULDBLOCK)
                {
                    // not blocking socket
                    continue;
                }
                else
                {
                    changeStatus("Tcp Socket receiving error: ", std::to_string(error), false);
                    PostMessage(g_main, WM_OFFLINE, 0, NULL);
                    break;
                }
            }
        }
    }
}

void udpListener()
{
    if (udpSocket != INVALID_SOCKET)
    {
        // Buffer for receiving UDP packets
        BYTE receivedData[MAX_PACKET_SIZE];

        while (running)
        {

            fd_set readfds;
            struct timeval tv;

            FD_ZERO(&readfds);
            FD_SET(udpSocket, &readfds);
            tv.tv_sec = 0;
            tv.tv_usec = 100000; // 10ms timeout

            // First parameter to select should be udpSocket + 1, not 0
            int selectResult = select(udpSocket + 1, &readfds, NULL, NULL, &tv);

            if (selectResult > 0)
            {
                sockaddr_in senderAddr;
                int senderAddrSize = sizeof(senderAddr);

                int bytesReceived = recvfrom(udpSocket, reinterpret_cast<char *>(receivedData), MAX_PACKET_SIZE, 0,
                                             reinterpret_cast<struct sockaddr *>(&senderAddr), &senderAddrSize);

                if (bytesReceived < 0)
                {
                    changeStatus("Error Udp receiving data: ", std::to_string(WSAGetLastError()), false);
                    continue;
                }

                else if (bytesReceived > 0)
                {
                    // Add or update peer
                    char addrStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(senderAddr.sin_addr), addrStr, INET_ADDRSTRLEN);

                    {
                        std::lock_guard<std::mutex> lock(peersMutex);

                        bool newPeer = !peer.active;

                        // if a new peer initialize values
                        if (newPeer)
                        {
                            peer.addr = std::string(addrStr);
                            peer.connectionStartTime = time(nullptr);
                            peer.totalActiveTime = 0;

                            changeStatus("Connected with: ", peer.addr, false);
                            SendMessage(g_main, WM_CONNECTED, 0, 0);
                        }

                        // Handle byte counting to avoid overflow

                        if (std::numeric_limits<uint64_t>::max() - peer.totalBytesReceived >= bytesReceived)
                        {
                            // Safe to add - no overflow will occur
                            peer.totalBytesReceived += bytesReceived;
                        }
                        else
                        {
                            // Handle potential overflow - either cap at max or wrap around
                            peer.totalBytesReceived = std::numeric_limits<uint64_t>::max();

                            // Or optionally log the overflow
                            changeStatus("Byte counter reached maximum value.", "", false);
                        }
                        peer.lastActivity = time(nullptr);
                        peer.active = true;
                    }
                    // Create vector from received data
                    std::vector<unsigned char> packet(receivedData, receivedData + bytesReceived);

                    // Push to decode queue
                    {
                        std::lock_guard<std::mutex> lock(decodeMutex);
                        decodeQueue.push(std::move(packet));
                    }
                }
            }

            // Check for inactive peers (no activity for 5 seconds)
            time_t currentTime = time(nullptr);
            {
                std::lock_guard<std::mutex> lock(peersMutex);

                if (peer.active && currentTime - peer.lastActivity > 5)
                {
                    changeStatus("Peer disconnected: ", peer.addr, false);
                    peer.active = false;
                }
            }

            // Small sleep to prevent CPU hogging
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

void tcpSender(SOCKET socket, const char *message, std::atomic<bool> &run)

{
    if (run && socket != INVALID_SOCKET)
    {
        if (send(socket, message, strlen(message), 0) == SOCKET_ERROR)
        {
            changeStatus("Socket sending error: ", std::to_string(WSAGetLastError()), true);
        }
        else
        {
            changeStatus("Message sent successfully.", "", false);
        }
    }
}

void statsMonitor()
{
    while (running)
    {
        time_t currentTime = time(nullptr);

        {
            std::lock_guard<std::mutex> lock(peersMutex);

            // only if peer is active
            if (peer.active)
            {
                // sum active time
                peer.totalActiveTime = currentTime - peer.connectionStartTime;

                // Format
                time_t activeTime = peer.totalActiveTime;
                int hours = activeTime / 3600;
                int minutes = (activeTime % 3600) / 60;
                int seconds = activeTime % 60;

                std::wostringstream wStatusStream;
                wStatusStream << hours << L":"
                              << std::setw(2) << std::setfill(L'0') << minutes << L":"
                              << std::setw(2) << std::setfill(L'0') << seconds;

                std::wstring wStatusText = wStatusStream.str();
                changeTitle(g_Stats, wStatusText.c_str(), false);

                // check inactive peer 5 secs
                if (currentTime - peer.lastActivity > 5)
                {

                    peer.active = false;
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

LRESULT CALLBACK WindowProc(HWND g_main, UINT uMsg, WPARAM wParam, LPARAM lParam)
{

    switch (uMsg)
    {

    case WM_CREATE:
        // Font Segoe UI
        hFont = CreateFont(17, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        // icona

        if (GetCurrentDirectory(MAX_PATH, currentDirectory))
        {
            _snwprintf(fullPath, MAX_PATH, L"%s\\%s", currentDirectory, fileIco);
            hIcon = (HICON)LoadImage(
                NULL,                             // Handle dell'istanza (NULL per file esterni)
                fullPath,                         // Percorso del file .ico
                IMAGE_ICON,                       // Tipo: icona
                32,                               // Larghezza desiderata
                32,                               // Altezza desiderata
                LR_LOADFROMFILE | LR_DEFAULTCOLOR // Caricare da file con i colori predefiniti
            );
        }
        SendMessage(g_main, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        // Creazione del pulsante
        // Creare un pulsante Owner-Draw
        g_BConnect = CreateWindow(
            L"BUTTON",
            L"Connect",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            160, 90,
            80, 40,
            g_main,
            (HMENU)ID_BUTTON_CONNECT,
            g_hInstance,
            NULL);

        g_BQuit = CreateWindow(
            L"BUTTON",
            L"Quit",
            WS_CHILD | BS_OWNERDRAW,
            160, 90,
            80, 40,
            g_main,
            (HMENU)ID_BUTTON_QUIT,
            g_hInstance,
            NULL);

        ShowWindow(g_BQuit, SW_HIDE);

        g_BAccept = CreateWindow(
            L"BUTTON",
            L"Accept",
            WS_CHILD | BS_OWNERDRAW,
            100, 90,
            80, 40,
            g_main,
            (HMENU)ID_BUTTON_ACCEPT,
            g_hInstance,
            NULL);

        ShowWindow(g_BAccept, SW_HIDE);

        g_BReject = CreateWindow(
            L"BUTTON",
            L"Reject",
            WS_CHILD | BS_OWNERDRAW,
            220, 90,
            80, 40,
            g_main,
            (HMENU)ID_BUTTON_REJECT,
            g_hInstance,
            NULL);

        ShowWindow(g_BReject, SW_HIDE);

        g_Title = CreateWindow(
            L"STATIC",
            L"Insert Ip to call",
            WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
            0, 0,
            400, 40,
            g_main,
            (HMENU)ID_STATIC_TITLE,
            g_hInstance,
            NULL);

        g_Stats = CreateWindow(
            L"STATIC",
            L"",
            WS_CHILD | SS_OWNERDRAW,
            0, 150,
            400, 60,
            g_main,
            (HMENU)ID_STATS,
            g_hInstance,
            NULL);

        ShowWindow(g_Stats, SW_HIDE);

        return 0;
    case WM_DRAWITEM:
    {
        DRAWITEMSTRUCT *pDIS = (DRAWITEMSTRUCT *)lParam;
        if (pDIS->CtlID == ID_BUTTON_CONNECT) // ID del pulsante
        {
            // Determina lo stato del pulsante
            BOOL isPressed = pDIS->itemState & ODS_SELECTED;
            BOOL isHover = pDIS->itemState & ODS_HOTLIGHT;

            // Scegli il colore in base allo stato
            COLORREF bgColor = RGB(0, 120, 215); // Blu normale
            if (isPressed)
                bgColor = RGB(0, 90, 158); // Blu scuro (premuto)
            else if (isHover)
                bgColor = RGB(16, 110, 190); // Blu medio (hover)

            // Disegna sfondo
            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(pDIS->hDC, &pDIS->rcItem, hBrush);
            DeleteObject(hBrush);

            // Disegna testo
            WCHAR text[256];
            GetWindowText(pDIS->hwndItem, text, 256);

            SetBkMode(pDIS->hDC, TRANSPARENT);
            SetTextColor(pDIS->hDC, RGB(255, 255, 255));

            HFONT hOldFont = (HFONT)SelectObject(pDIS->hDC, hFont);

            DrawText(pDIS->hDC, text, -1, &pDIS->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(pDIS->hDC, hOldFont);

            return TRUE;
        }
        if (pDIS->CtlID == ID_BUTTON_QUIT) // ID del pulsante
        {
            // Determina lo stato del pulsante
            BOOL isPressed = pDIS->itemState & ODS_SELECTED;
            BOOL isHover = pDIS->itemState & ODS_HOTLIGHT;

            // Scegli il colore in base allo stato
            COLORREF bgColor = RGB(240, 10, 10); // Ross normale
            if (isPressed)
                bgColor = RGB(139, 10, 10); // Ross scuro (premuto)
            else if (isHover)
                bgColor = RGB(200, 10, 10); // Rosso medio (hover)

            // Disegna sfondo
            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(pDIS->hDC, &pDIS->rcItem, hBrush);
            DeleteObject(hBrush);

            // Disegna testo
            WCHAR text[256];
            GetWindowText(pDIS->hwndItem, text, 256);

            SetBkMode(pDIS->hDC, TRANSPARENT);
            SetTextColor(pDIS->hDC, RGB(255, 255, 255));

            HFONT hOldFont = (HFONT)SelectObject(pDIS->hDC, hFont);

            DrawText(pDIS->hDC, text, -1, &pDIS->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(pDIS->hDC, hOldFont);

            return TRUE;
        }

        if (pDIS->CtlID == ID_BUTTON_ACCEPT) // ID del pulsante
        {
            // Determina lo stato del pulsante
            BOOL isPressed = pDIS->itemState & ODS_SELECTED;
            BOOL isHover = pDIS->itemState & ODS_HOTLIGHT;

            // Scegli il colore in base allo stato
            COLORREF bgColor = RGB(0, 128, 10); // verde normale
            if (isPressed)
                bgColor = RGB(0, 80, 10); // verde scuro (premuto)
            else if (isHover)
                bgColor = RGB(0, 100, 10); // verde medio (hover)

            // Disegna sfondo
            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(pDIS->hDC, &pDIS->rcItem, hBrush);
            DeleteObject(hBrush);

            // Disegna testo
            WCHAR text[256];
            GetWindowText(pDIS->hwndItem, text, 256);

            SetBkMode(pDIS->hDC, TRANSPARENT);
            SetTextColor(pDIS->hDC, RGB(255, 255, 255));

            HFONT hOldFont = (HFONT)SelectObject(pDIS->hDC, hFont);

            DrawText(pDIS->hDC, text, -1, &pDIS->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(pDIS->hDC, hOldFont);

            return TRUE;
        }

        if (pDIS->CtlID == ID_BUTTON_REJECT) // ID del pulsante
        {
            // Determina lo stato del pulsante
            BOOL isPressed = pDIS->itemState & ODS_SELECTED;
            BOOL isHover = pDIS->itemState & ODS_HOTLIGHT;

            // Scegli il colore in base allo stato
            COLORREF bgColor = RGB(240, 10, 10); // Ross normale
            if (isPressed)
                bgColor = RGB(139, 10, 10); // Ross scuro (premuto)
            else if (isHover)
                bgColor = RGB(200, 10, 10); // Rosso medio (hover)

            // Disegna sfondo
            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(pDIS->hDC, &pDIS->rcItem, hBrush);
            DeleteObject(hBrush);

            // Disegna testo
            WCHAR text[256];
            GetWindowText(pDIS->hwndItem, text, 256);

            SetBkMode(pDIS->hDC, TRANSPARENT);
            SetTextColor(pDIS->hDC, RGB(255, 255, 255));

            HFONT hOldFont = (HFONT)SelectObject(pDIS->hDC, hFont);

            DrawText(pDIS->hDC, text, -1, &pDIS->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(pDIS->hDC, hOldFont);

            return TRUE;
        }

        if (pDIS->CtlID == ID_STATIC_TITLE)
        {
            // Ottieni il testo del controllo
            WCHAR szText[256] = {0};
            GetWindowText(pDIS->hwndItem, szText, 256);

            // Prepara il contesto del dispositivo
            HDC hdc = pDIS->hDC;
            RECT rc = pDIS->rcItem;

            // Imposta il colore di sfondo bianco
            SetBkColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, TRANSPARENT);

            // Riempi lo sfondo con bianco
            HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 255));
            FillRect(hdc, &rc, hBrush);
            DeleteObject(hBrush);

            // Seleziona il font personalizzato
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);

            // Imposta il colore del testo (nero in questo caso)
            SetTextColor(hdc, RGB(0, 0, 0));

            // Disegna il testo centrato
            DrawText(hdc, szText, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            // Ripristina il font originale
            SelectObject(hdc, hOldFont);

            return TRUE; // Abbiamo gestito il messaggio
        }
        if (pDIS->CtlID == ID_STATS)
        {
            // Ottieni il testo del controllo
            WCHAR szText[256] = {0};
            GetWindowText(pDIS->hwndItem, szText, 256);

            // Prepara il contesto del dispositivo
            HDC hdc = pDIS->hDC;
            RECT rc = pDIS->rcItem;

            // Imposta il colore di sfondo bianco
            SetBkColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, TRANSPARENT);

            // Riempi lo sfondo con bianco
            HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 255));
            FillRect(hdc, &rc, hBrush);
            DeleteObject(hBrush);

            // Seleziona il font personalizzato
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);

            // Imposta il colore del testo (nero in questo caso)
            SetTextColor(hdc, RGB(0, 0, 0));

            // Disegna il testo centrato
            DrawText(hdc, szText, -1, &rc, DT_CENTER | DT_VCENTER | DT_WORDBREAK);

            // Ripristina il font originale
            SelectObject(hdc, hOldFont);

            return TRUE;
        }
        break;
    }

    case WM_GETMINMAXINFO:
    {
        MINMAXINFO *pMinMax = (MINMAXINFO *)lParam;
        // Imposta dimensioni minime e massime uguali per rendere la finestra fissa
        pMinMax->ptMinTrackSize.x = 400; // Larghezza fissa
        pMinMax->ptMinTrackSize.y = 400; // Altezza fissa
        pMinMax->ptMaxTrackSize.x = 400; // Larghezza fissa
        pMinMax->ptMaxTrackSize.y = 400; // Altezza fissa
        return 0;
    }

        /*     case WM_UPDATE_STATUS:

            {
                std::string *statusText = (std::string *)lParam;
                std::wstring wStatusText(statusText->begin(), statusText->end());
                SendMessage(g_StatusBar, SB_SETTEXT, 0, (LPARAM)wStatusText.c_str());
                delete statusText;
                return 0;
            }
         */
    case WM_CONNECTING:

    {
        tcpConnecting();
        const char *message = addComputerName(hello);
        if (clientRunning)
        {
            tcpSender(clientSocket, message, clientRunning);
        }
        changeTitle(g_Title, L"Call send", false);
        delete[] message;
        return 0;
    }

    case WM_CONNECTED:

    {
        changeTitle(g_Title, L"Call in progress", false);

        // hide/show controller
        ShowWindow(g_BConnect, SW_HIDE);
        ShowWindow(g_BAccept, SW_HIDE);
        ShowWindow(g_BReject, SW_HIDE);
        EnableWindow(g_BQuit, TRUE);
        ShowWindow(g_BQuit, SW_SHOW);
        EnableWindow(g_Stats, TRUE);
        ShowWindow(g_Stats, SW_SHOW);
        return 0;
    }

    case WM_INCOMING:
    {
        // extract computer name of incoming call
        std::wstring t1 = L"Call incoming from: ";
        std::wstring t2(peer.name.begin(), peer.name.end());
        std::wstring t1Converted = t1 + t2;
        changeTitle(g_Title, t1Converted.c_str(), false);

        ShowWindow(g_BConnect, SW_HIDE);
        EnableWindow(g_BAccept, TRUE);
        ShowWindow(g_BAccept, SW_SHOW);
        EnableWindow(g_BReject, TRUE);
        ShowWindow(g_BReject, SW_SHOW);
        return 0;
    }
    case WM_BUSY:

    {
        changeTitle(g_Title, L"User busy, try Later", true);
        Sleep(5000);
        PostMessage(g_main, WM_RESET, 0, 0);
        return 0;
    }

    case WM_REJECT:

    {
        changeTitle(g_Title, L"Call rejected", true);
        cleanupSocket(clientSocket);
        Sleep(5000);
        PostMessage(g_main, WM_RESET, 0, 0);

        return 0;
    }

    case WM_OFFLINE:

    {
        clientRunning = false;
        cleanupSocket(clientSocket);
        changeTitle(g_Title, L"User offline, try later", false);
        Sleep(5000);
        PostMessage(g_main, WM_RESET, 0, 0);
        return 0;
    }

    case WM_CALL_ENDING:
    {
        if (clientRunning.load())
        {
            tcpSender(clientSocket, close, clientRunning);
            clientRunning = false;
            cleanupSocket(clientSocket);
        }
        else
        {
            tcpSender(acceptSocket, close, serverRunning);
        }
        return 0;
    }
    case WM_CALL_END:
    {
        running = false;

        cleanupSocket(clientSocket);
        Sleep(50);
        cleanupSocket(udpSocket);
        Sleep(50);
        cleanupSocket(acceptSocket);
        Sleep(50);
        changeTitle(g_Title, L"Call end", true);

        time_t activeTime = peer.totalActiveTime;
        int hours = activeTime / 3600;
        int minutes = (activeTime % 3600) / 60;
        int seconds = activeTime % 60;

        std::wostringstream wStatusStream;
        wStatusStream << L"Duration: " << hours << L":"
                      << std::setw(2) << std::setfill(L'0') << minutes << L":"
                      << std::setw(2) << std::setfill(L'0') << seconds << L"\r\nBytes Sent: "
                      << peer.totalBytesSent << L"\r\nBytes Received: " << peer.totalBytesReceived;

        std::wstring wStatusText = wStatusStream.str();
        changeTitle(g_Stats, wStatusText.c_str(), false);

        {
            std::lock_guard<std::mutex> lock(captureMutex);
            while (!captureQueue.empty())
            {
                delete[] captureQueue.front().data;
                captureQueue.pop();
            }
        }
        Sleep(5000);
        PostMessage(g_main, WM_RESET, 0, 0);
        return 0;
    }
    case WM_RESET:
    {
        // Set state flags first to stop any ongoing operations
        running = false;
        serverRunning = false;
        clientRunning = false;
        SetEvent(stopThreadsEvent);
        Sleep(100);

        // Safely close sockets - check if valid first
        cleanupSocket(serverSocket);
        cleanupSocket(clientSocket);
        cleanupSocket(udpSocket);
        cleanupSocket(acceptSocket);

        // ReInitialize the server socket
        initSocket(serverSocket, IPPROTO_TCP, serverPort);

        // Update UI
        EnableWindow(g_BQuit, FALSE);
        ShowWindow(g_BQuit, SW_HIDE);
        EnableWindow(g_Stats, FALSE);
        ShowWindow(g_Stats, SW_HIDE);
        EnableWindow(g_BAccept, FALSE);
        ShowWindow(g_BAccept, SW_HIDE);
        EnableWindow(g_BReject, FALSE);
        ShowWindow(g_BReject, SW_HIDE);
        EnableWindow(g_BConnect, TRUE);
        ShowWindow(g_BConnect, SW_SHOW);

        // Reset peer info
        {
            std::lock_guard<std::mutex> lock(peersMutex);
            peer = Peer();
        }

        // Safely handle threads - use a helper function to restart threads if needed
        restartThreadsIfNeeded();
        SetWindowText(g_Title, L"Insert IP to call");
        changeStatus("Ready", "", false);
        return 0;
    }

    case WM_ACCEPT:
    {
        initSocket(udpSocket, IPPROTO_UDP, udpPort);
        Sleep(50);
        running = true;
        Sleep(50);
        changeTitle(g_Title, L"Call accepts, attempts to stabilize connection", false);
        Sleep(50);
        // if accept start udp connection
        if (clientRunning)
        {
            udpConnecting();
        }
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BUTTON_CONNECT && HIWORD(wParam) == BN_CLICKED)
        {
            PostMessage(g_main, WM_CONNECTING, 0, 0);
        }

        if (LOWORD(wParam) == ID_BUTTON_QUIT && HIWORD(wParam) == BN_CLICKED)
        {
            PostMessage(g_main, WM_CALL_ENDING, 0, 0);
            PostMessage(g_main, WM_CALL_END, 0, 0);
        }

        if (LOWORD(wParam) == ID_BUTTON_ACCEPT && HIWORD(wParam) == BN_CLICKED)
        {
            const char *message = addComputerName(Vaccept);
            tcpSender(acceptSocket, message, serverRunning);
            delete[] message;
            PostMessage(g_main, WM_ACCEPT, 0, 0);
        }

        if (LOWORD(wParam) == ID_BUTTON_REJECT && HIWORD(wParam) == BN_CLICKED)
        {

            tcpSender(acceptSocket, reject, serverRunning);

            Sleep(5000);
            PostMessage(g_main, WM_RESET, 0, 0);
        }

        return 0;

    case WM_DESTROY:

    {
        if (clientRunning)
        {
            tcpSender(clientSocket, close, clientRunning);
        }
        else
        {
            tcpSender(acceptSocket, close, serverRunning);
        }
        running = false;

        serverRunning = false;
        clientRunning = false;

        closesocket(serverSocket);
        closesocket(clientSocket);
        closesocket(acceptSocket);
        closesocket(udpSocket);

        WSACleanup();
        PostQuitMessage(0);

        DestroyIcon(hIcon);

        if (hFont)
        {
            DeleteObject(hFont);
        }

        return 0;
    }
    default:
        return DefWindowProc(g_main, uMsg, wParam, lParam);
    }
}

int WINAPI WinMain(HINSTANCE g_hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    const wchar_t CLASS_NAME[] = L"MyWindowClass";

    // Register class for windows
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = g_hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClass(&wc);

    // Creazione della finestra
    g_main = CreateWindowEx(
        0,                            // Stile esteso della finestra
        CLASS_NAME,                   // Nome della classe
        L"VOIP APP",                  // Titolo della finestra
        WS_OVERLAPPEDWINDOW,          // Stile della finestra
        CW_USEDEFAULT, CW_USEDEFAULT, // Posizione iniziale
        400, 400,                     // Dimensioni iniziali
        NULL,                         // Nessuna finestra padre
        NULL,                         // Nessun menu
        g_hInstance,                  // Handle dell'istanza
        NULL                          // Nessun parametro di creazione
    );

    if (g_main == NULL)
    {
        return 0;
    }

    ShowWindow(g_main, nCmdShow);

    // Creazione della edit box per l'indirizzo IP
    g_IPBox = CreateWindowEx(
        0,
        WC_IPADDRESS, // Classe standard per controlli IP
        L"IP Address ",
        WS_CHILD | WS_VISIBLE | WS_BORDER | DT_CENTER,
        125, 50,         // Posizione
        150, 25,         // Dimensione
        g_main,          // Handle della finestra padre
        (HMENU)ID_IPBOX, // Nessun ID del controllo
        g_hInstance,
        NULL);

    g_StatusBar = CreateWindow(
        STATUSCLASSNAME,
        L"Ready",
        WS_CHILD | WS_VISIBLE,
        0, 0, 0, 0,
        g_main,
        (HMENU)ID_STATUSBAR,
        g_hInstance,
        NULL);

    // socket

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        changeStatus("WSAStartup failed", "", false);
    }

    initSocket(serverSocket, IPPROTO_TCP, serverPort);

    // event for stopping sockets threads
    stopThreadsEvent = CreateEvent(
        NULL,  // secure attributes, default
        TRUE,  // manual event reset
        FALSE, // initial state
        NULL   // nessun nome
    );
    // error
    if (stopThreadsEvent == NULL)
    {

        changeStatus("Failed to create sync event", std::to_string(GetLastError()), false);
    }

    // start audio thread
    captureThread = std::thread(captureAudio);
    captureThread.detach();
    encodeThread = std::thread(encodeAudio);
    encodeThread.detach();

    decodeThread = std::thread(decodeAudio);
    decodeThread.detach();
    playbackThread = std::thread(playbackAudio);
    playbackThread.detach();
    udpListenerThread = std::thread(udpListener);
    udpListenerThread.detach();
    statsThread = std::thread(statsMonitor);
    statsThread.detach();

    // Msgs loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}