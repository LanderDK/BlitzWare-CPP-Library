#include "BlitzWareAuth.h"

namespace BlitzWare {
	std::string Security::CalculateResponseHash(const std::string& data) {
		unsigned char hash[SHA256_DIGEST_LENGTH];
		EVP_MD_CTX* mdctx;
		const EVP_MD* md = EVP_sha256();

		mdctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(mdctx, md, NULL);
		EVP_DigestUpdate(mdctx, data.c_str(), data.length());
		EVP_DigestFinal_ex(mdctx, hash, NULL);
		EVP_MD_CTX_free(mdctx);

		std::stringstream ss;
		ss << std::hex << std::setfill('0');
		for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		{
			ss << std::setw(2) << static_cast<unsigned>(hash[i]);
		}

		return ss.str();
	}

	std::string Security::CalculateFileHash(const char* filename) {
		std::string result;
		std::ifstream file(filename, std::ios::binary);

		if (file.is_open())
		{
			file.seekg(0, std::ios::end);
			std::streampos size = file.tellg();
			file.seekg(0, std::ios::beg);
			char* buffer = new char[size];
			file.read(buffer, size);
			file.close();

			unsigned char hash[SHA256_DIGEST_LENGTH];
			SHA256((unsigned char*)buffer, size, hash);

			std::stringstream ss;
			for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
			{
				ss << std::setfill('0') << std::setw(2) << std::hex << (int)hash[i];
			}
			result = ss.str();
			delete[] buffer;
		}
		return result;
	}

	std::string Utilities::RemoveQuotesFromString(const std::string& s) {
		std::string result = s;
		if (!result.empty() && (result.front() == '"' || result.back() == '"')) {
			result.erase(result.begin());
			result.pop_back();
		}
		return result;
	}

	std::string Utilities::HWID() {
		std::string hwid;

		FILE* pipe = _popen("wmic diskdrive get serialnumber", "r"); // Use _popen directly
		if (!pipe)
			hwid = "Error hwid"; // Error opening pipe
		else {
			char buffer[128];
			// Read and discard the first line
			if (fgets(buffer, sizeof(buffer), pipe)) {
				// Read the second line
				if (fgets(buffer, sizeof(buffer), pipe)) {
					hwid = buffer;
					// Remove all leading and trailing whitespace characters, including dot
					size_t lastCharPos = hwid.find_last_not_of(" \t\n\r\f\v.");
					if (lastCharPos != std::string::npos) {
						hwid = hwid.substr(0, lastCharPos + 1);
					}
				}
			}
		}

		_pclose(pipe); // Use _pclose directly
		return hwid;
	}

	std::string Utilities::IP() {
		auto response = cpr::Get // or cpr::Head
		(
			cpr::Url{ "http://icanhazip.com" },
			cpr::Header{ {"accept", "text/html"} },
			cpr::Timeout{ 4 * 1000 }
		);

		std::string ip = response.text;

		// Remove all leading and trailing whitespace characters, including dot
		size_t lastCharPos = ip.find_last_not_of(" \t\n\r\f\v.");
		if (lastCharPos != std::string::npos) {
			ip = ip.substr(0, lastCharPos + 1);
		}

		return ip;
	}

	API::API(const std::string& apiUrl, const std::string& appName, const std::string& appSecret, const std::string& appVersion)
		: apiUrl(apiUrl), appName(appName), appSecret(appSecret), appVersion(appVersion), initialized(false) {}

	void API::Initialize() {
		try
		{
			json::json AppInitDetails;
			AppInitDetails["name"] = this->appName;
			AppInitDetails["secret"] = this->appSecret;
			AppInitDetails["version"] = this->appVersion;
			auto response = cpr::Post(cpr::Url{ this->apiUrl + "applications/initialize" },
				cpr::Body{ AppInitDetails.dump() },
				cpr::Header{ {"Content-Type", "application/json"} });
			json::json content;
			auto receivedHash = response.header["X-Response-Hash"];
			std::string recalculatedHash = BlitzWare::Security::CalculateResponseHash(response.text);

			if (receivedHash != recalculatedHash)
			{
				MessageBoxA(NULL, "Possible malicious activity detected!", this->appName.c_str(), MB_ICONEXCLAMATION | MB_OK);
				exit(0);
			}

			if (response.status_code == 200)
			{
				content = json::json::parse(response.text);
				this->initialized = true;
				BlitzWare::API::ApplicationData::id = BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["id"]));
				BlitzWare::API::ApplicationData::name = BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["name"]));
				BlitzWare::API::ApplicationData::status = content["status"] == 1 ? true : false;
				BlitzWare::API::ApplicationData::hwidCheck = content["hwidCheck"] == 1 ? true : false;
				BlitzWare::API::ApplicationData::integrityCheck = content["integrityCheck"] == 1 ? true : false;
				BlitzWare::API::ApplicationData::programHash = BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["programHash"]));
				BlitzWare::API::ApplicationData::version = BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["version"]));
				BlitzWare::API::ApplicationData::downloadLink = BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["downloadLink"]));
				BlitzWare::API::ApplicationData::developerMode = content["developerMode"] == 1 ? true : false;
				BlitzWare::API::ApplicationData::freeMode = content["freeMode"] == 1 ? true : false;
				BlitzWare::API::ApplicationData::twoFactorAuth = content["twoFactorAuth"] == 1 ? true : false;


				if (!BlitzWare::API::ApplicationData::status)
				{
					MessageBoxA(NULL, "Looks like this application is offline, please try again later!", BlitzWare::API::ApplicationData::name.c_str(),
						MB_ICONERROR | MB_OK);
					exit(0);
				}

				if (BlitzWare::API::ApplicationData::freeMode)
					MessageBoxA(NULL, "Application is in Free Mode!", BlitzWare::API::ApplicationData::name.c_str(),
						MB_ICONINFORMATION | MB_OK);

				if (BlitzWare::API::ApplicationData::developerMode)
				{
					MessageBoxA(NULL, "Application is in Developer Mode, bypassing integrity and update check!", BlitzWare::API::ApplicationData::name.c_str(), MB_OK | MB_ICONWARNING);

					// Get the full path of the current executable
					WCHAR buffer[MAX_PATH];
					GetModuleFileName(NULL, buffer, MAX_PATH);

					// Convert the wide character string to a regular string
					char fullPath[MAX_PATH];
					size_t convertedChars = 0;
					wcstombs_s(&convertedChars, fullPath, MAX_PATH, buffer, _TRUNCATE);

					// Check if the conversion was successful
					if (convertedChars == static_cast<size_t>(-1))
					{
						// Handle the conversion error here.
					}
					else
					{
						// Get the directory path of the current file
						std::string dirPath = fullPath;
						dirPath = dirPath.substr(0, dirPath.find_last_of("\\/"));

						// Save hash of current file in "integrity.text"
						// When you release your progam you should disable "Developer Mod", enable "Integrity Check" and
						// paste the value in "integrity.text" in the "Program Hash" field on the dashboard.
						std::ofstream integrity_log("integrity.txt");
						if (integrity_log.is_open())
						{
							std::string hash = BlitzWare::Security::CalculateFileHash(fullPath);
							integrity_log << hash << std::endl;
							integrity_log.close();
							MessageBoxA(NULL, "Your application's hash has been saved to integrity.txt, please refer to this when your application is ready for release!", BlitzWare::API::ApplicationData::name.c_str(), MB_OK | MB_ICONINFORMATION);
						}
					}

				}
				else
				{
					if (BlitzWare::API::ApplicationData::version != appVersion)
					{
						MessageBoxA(NULL, "Update is available, redirecting to update!", BlitzWare::API::ApplicationData::name.c_str(),
							MB_ICONERROR | MB_OK);
						system(std::string("start " + BlitzWare::API::ApplicationData::downloadLink).c_str());
						exit(0);
					}
					if (BlitzWare::API::ApplicationData::integrityCheck)
					{
						// Get the full path of the current executable
						WCHAR buffer[MAX_PATH];
						GetModuleFileName(NULL, buffer, MAX_PATH);

						// Convert the wide character string to a regular string
						char fullPath[MAX_PATH];
						size_t convertedChars = 0;
						wcstombs_s(&convertedChars, fullPath, MAX_PATH, buffer, _TRUNCATE);

						// Check if the conversion was successful
						if (convertedChars == static_cast<size_t>(-1))
						{
							// Handle the conversion error here.
						}
						else
						{
							// Get the directory path of the current file
							std::string dirPath = fullPath;
							dirPath = dirPath.substr(0, dirPath.find_last_of("\\/"));

							// Check the integrity of the file
							if (BlitzWare::API::ApplicationData::programHash != BlitzWare::Security::CalculateFileHash(fullPath))
							{
								MessageBoxA(NULL, "File has been tampered with, couldn't verify integrity!", BlitzWare::API::ApplicationData::name.c_str(),
									MB_ICONERROR | MB_OK);
								exit(0);
							}
						}

					}
				}
			}
			else
			{
				content = json::json::parse(response.text);
				if (response.status_code == 0)
				{
					MessageBoxA(NULL, "Unable to connect to the remote server!", this->appName.c_str(), MB_ICONERROR | MB_OK);
					exit(0);
				}
				if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), this->appName.c_str(), MB_ICONERROR | MB_OK);
					exit(0);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "FORBIDDEN")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), this->appName.c_str(), MB_ICONERROR | MB_OK);
					exit(0);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
				{
					MessageBoxA(NULL, "Failed to initialize your application correctly!", this->appName.c_str(), MB_ICONERROR | MB_OK);
					exit(0);
				}
			}
		}
		catch (const std::exception& ex)
		{
			MessageBoxA(NULL, "Unkown error, contact support!", this->appName.c_str(), MB_ICONERROR | MB_OK);
			std::cout << ex.what() << std::endl;
		}
	}

	bool API::Register(const std::string& username, const std::string& password, const std::string& email, const std::string& license) {
		if (!this->initialized)
		{
			MessageBoxA(NULL, "Please initialize your application first!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
			return false;
		}
		try
		{
			json::json UserRegisterDetails;
			UserRegisterDetails["username"] = username;
			UserRegisterDetails["password"] = password;
			UserRegisterDetails["email"] = email;
			UserRegisterDetails["license"] = license;
			UserRegisterDetails["hwid"] = BlitzWare::Utilities::HWID();
			UserRegisterDetails["lastIP"] = BlitzWare::Utilities::IP();
			UserRegisterDetails["id"] = BlitzWare::API::ApplicationData::id;
			auto response = cpr::Post(cpr::Url{ this->apiUrl + "users/register" },
				cpr::Body{ UserRegisterDetails.dump() },
				cpr::Header{ {"Content-Type", "application/json"} });
			json::json content;
			auto receivedHash = response.header["X-Response-Hash"];
			std::string recalculatedHash = BlitzWare::Security::CalculateResponseHash(response.text);

			if (receivedHash != recalculatedHash)
			{
				MessageBoxA(NULL, "Possible malicious activity detected!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONEXCLAMATION | MB_OK);
				exit(0);
			}

			if (response.status_code == 200 || response.status_code == 201)
			{
				content = json::json::parse(response.text);
				BlitzWare::API::UserData::id = BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["user"]["id"]));
				BlitzWare::API::UserData::username = Utilities::RemoveQuotesFromString(to_string(content["user"]["username"]));
				BlitzWare::API::UserData::email = Utilities::RemoveQuotesFromString(to_string(content["user"]["email"]));
				BlitzWare::API::UserData::expiry = Utilities::RemoveQuotesFromString(to_string(content["user"]["expiryDate"]));
				BlitzWare::API::UserData::lastLogin = Utilities::RemoveQuotesFromString(to_string(content["user"]["lastLogin"]));
				BlitzWare::API::UserData::lastIP = Utilities::RemoveQuotesFromString(to_string(content["user"]["lastIP"]));
				BlitzWare::API::UserData::hwid = Utilities::RemoveQuotesFromString(to_string(content["user"]["hwid"]));
				BlitzWare::API::UserData::authToken = Utilities::RemoveQuotesFromString(to_string(content["token"]));
				return true;
			}
			else
			{
				content = json::json::parse(response.text);
				if (response.status_code == 0)
				{
					MessageBoxA(NULL, "Unable to connect to the remote server!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "FORBIDDEN")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "UNAUTHORIZED")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
				{
					MessageBoxA(NULL, "Missing register data!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				return false;
			}
		}
		catch (const std::exception& ex)
		{
			std::cout << ex.what() << std::endl;
			MessageBoxA(NULL, "Unkown error, contact support!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
			return false;
		}
	}

	bool API::Login(const std::string& username, const std::string& password, const std::string& twoFactorCode) {
		if (!this->initialized)
		{
			MessageBoxA(NULL, "Please initialize your application first!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
			return false;
		}
		try
		{
			json::json UserLoginDetails;
			UserLoginDetails["username"] = username;
			UserLoginDetails["password"] = password;
			UserLoginDetails["twoFactorCode"] = twoFactorCode;
			UserLoginDetails["hwid"] = BlitzWare::Utilities::HWID();
			UserLoginDetails["lastIP"] = BlitzWare::Utilities::IP();
			UserLoginDetails["appId"] = BlitzWare::API::ApplicationData::id;
			auto response = cpr::Post(cpr::Url{ this->apiUrl + "users/login" },
				cpr::Body{ UserLoginDetails.dump() },
				cpr::Header{ {"Content-Type", "application/json"} });
			json::json content;
			auto receivedHash = response.header["X-Response-Hash"];
			std::string recalculatedHash = BlitzWare::Security::CalculateResponseHash(response.text);

			if (receivedHash != recalculatedHash)
			{
				MessageBoxA(NULL, "Possible malicious activity detected!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONEXCLAMATION | MB_OK);
				exit(0);
			}

			if (response.status_code == 200)
			{
				content = json::json::parse(response.text);
				BlitzWare::API::UserData::id = BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["user"]["id"]));
				BlitzWare::API::UserData::username = Utilities::RemoveQuotesFromString(to_string(content["user"]["username"]));
				BlitzWare::API::UserData::email = Utilities::RemoveQuotesFromString(to_string(content["user"]["email"]));
				BlitzWare::API::UserData::expiry = Utilities::RemoveQuotesFromString(to_string(content["user"]["expiryDate"]));
				BlitzWare::API::UserData::lastLogin = Utilities::RemoveQuotesFromString(to_string(content["user"]["lastLogin"]));
				BlitzWare::API::UserData::lastIP = Utilities::RemoveQuotesFromString(to_string(content["user"]["lastIP"]));
				BlitzWare::API::UserData::hwid = Utilities::RemoveQuotesFromString(to_string(content["user"]["hwid"]));
				BlitzWare::API::UserData::authToken = Utilities::RemoveQuotesFromString(to_string(content["token"]));
				return true;
			}
			else
			{
				content = json::json::parse(response.text);
				if (response.status_code == 0)
				{
					MessageBoxA(NULL, "Unable to connect to the remote server!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "FORBIDDEN")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "UNAUTHORIZED")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
				{
					MessageBoxA(NULL, "Missing login data!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				return false;
			}
		}
		catch (const std::exception& ex)
		{
			std::cout << ex.what() << std::endl;
			MessageBoxA(NULL, "Unkown error, contact support!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
			return false;
		}
	}

	bool API::LoginLicenseOnly(const std::string& license) {
		if (!this->initialized)
		{
			MessageBoxA(NULL, "Please initialize your application first!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
			return false;
		}
		try
		{
			json::json UserLoginDetails;
			UserLoginDetails["license"] = license;
			UserLoginDetails["hwid"] = BlitzWare::Utilities::HWID();
			UserLoginDetails["lastIP"] = BlitzWare::Utilities::IP();
			UserLoginDetails["appId"] = BlitzWare::API::ApplicationData::id;
			auto response = cpr::Post(cpr::Url{ this->apiUrl + "licenses/login" },
				cpr::Body{ UserLoginDetails.dump() },
				cpr::Header{ {"Content-Type", "application/json"} });
			json::json content;
			auto receivedHash = response.header["X-Response-Hash"];
			std::string recalculatedHash = BlitzWare::Security::CalculateResponseHash(response.text);

			if (receivedHash != recalculatedHash)
			{
				MessageBoxA(NULL, "Possible malicious activity detected!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONEXCLAMATION | MB_OK);
				exit(0);
			}

			if (response.status_code == 200)
			{
				content = json::json::parse(response.text);
				BlitzWare::API::UserData::id = BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["user"]["id"]));
				BlitzWare::API::UserData::username = Utilities::RemoveQuotesFromString(to_string(content["user"]["username"]));
				BlitzWare::API::UserData::email = Utilities::RemoveQuotesFromString(to_string(content["user"]["email"]));
				BlitzWare::API::UserData::expiry = Utilities::RemoveQuotesFromString(to_string(content["user"]["expiryDate"]));
				BlitzWare::API::UserData::lastLogin = Utilities::RemoveQuotesFromString(to_string(content["user"]["lastLogin"]));
				BlitzWare::API::UserData::lastIP = Utilities::RemoveQuotesFromString(to_string(content["user"]["lastIP"]));
				BlitzWare::API::UserData::hwid = Utilities::RemoveQuotesFromString(to_string(content["user"]["hwid"]));
				BlitzWare::API::UserData::authToken = Utilities::RemoveQuotesFromString(to_string(content["token"]));
				return true;
			}
			else
			{
				content = json::json::parse(response.text);
				if (response.status_code == 0)
				{
					MessageBoxA(NULL, "Unable to connect to the remote server!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "FORBIDDEN")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "UNAUTHORIZED")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
				{
					MessageBoxA(NULL, "Missing login data!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				return false;
			}
		}
		catch (const std::exception& ex)
		{
			std::cout << ex.what() << std::endl;
			MessageBoxA(NULL, "Unkown error, contact support!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
			return false;
		}
	}

	bool API::Extend(const std::string& username, const std::string& password, const std::string& license) {
		if (!this->initialized)
		{
			MessageBoxA(NULL, "Please initialize your application first!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
			return false;
		}
		try
		{
			json::json UserExtendDetails;
			UserExtendDetails["username"] = username;
			UserExtendDetails["password"] = password;
			UserExtendDetails["license"] = license;
			UserExtendDetails["hwid"] = BlitzWare::Utilities::HWID();
			UserExtendDetails["appId"] = BlitzWare::API::ApplicationData::id;
			auto response = cpr::Put(cpr::Url{ this->apiUrl + "users/upgrade" },
				cpr::Body{ UserExtendDetails.dump() },
				cpr::Header{ {"Content-Type", "application/json"} });
			json::json content;
			auto receivedHash = response.header["X-Response-Hash"];
			std::string recalculatedHash = BlitzWare::Security::CalculateResponseHash(response.text);

			if (receivedHash != recalculatedHash)
			{
				MessageBoxA(NULL, "Possible malicious activity detected!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONEXCLAMATION | MB_OK);
				exit(0);
			}

			if (response.status_code == 200)
			{
				content = json::json::parse(response.text);
				BlitzWare::API::UserData::id = BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["user"]["id"]));
				BlitzWare::API::UserData::username = Utilities::RemoveQuotesFromString(to_string(content["user"]["username"]));
				BlitzWare::API::UserData::email = Utilities::RemoveQuotesFromString(to_string(content["user"]["email"]));
				BlitzWare::API::UserData::expiry = Utilities::RemoveQuotesFromString(to_string(content["user"]["expiryDate"]));
				BlitzWare::API::UserData::lastLogin = Utilities::RemoveQuotesFromString(to_string(content["user"]["lastLogin"]));
				BlitzWare::API::UserData::lastIP = Utilities::RemoveQuotesFromString(to_string(content["user"]["lastIP"]));
				BlitzWare::API::UserData::hwid = Utilities::RemoveQuotesFromString(to_string(content["user"]["hwid"]));
				BlitzWare::API::UserData::authToken = Utilities::RemoveQuotesFromString(to_string(content["token"]));
				return true;
			}
			else
			{
				content = json::json::parse(response.text);
				if (response.status_code == 0)
				{
					MessageBoxA(NULL, "Unable to connect to the remote server!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "FORBIDDEN")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "UNAUTHORIZED")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
				{
					MessageBoxA(NULL, "Missing extend data!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				return false;
			}
		}
		catch (const std::exception& ex)
		{
			std::cout << ex.what() << std::endl;
			MessageBoxA(NULL, "Unkown error, contact support!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
			return false;
		}
	}

	void API::Log(const std::string& username, const std::string& action) {
		if (!this->initialized)
		{
			MessageBoxA(NULL, "Please initialize your application first!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
		}
		try
		{
			json::json AppLogsDetails;
			AppLogsDetails["username"] = username;
			AppLogsDetails["action"] = action;
			AppLogsDetails["ip"] = BlitzWare::Utilities::IP();
			AppLogsDetails["appId"] = BlitzWare::API::ApplicationData::id;
			auto response = cpr::Post(cpr::Url{ this->apiUrl + "appLogs/" },
				cpr::Body{ AppLogsDetails.dump() },
				cpr::Header{ {"Content-Type", "application/json"},
				{"Authorization", "Bearer " + BlitzWare::API::UserData::authToken} });
			json::json content;

			if (response.status_code != 201)
			{
				content = json::json::parse(response.text);
				if (response.status_code == 0)
				{
					MessageBoxA(NULL, "Unable to connect to the remote server!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "NOT_FOUND")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "FORBIDDEN")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "UNAUTHORIZED")
				{
					MessageBoxA(NULL, BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["message"])).c_str(), BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
				else if (BlitzWare::Utilities::RemoveQuotesFromString(to_string(content["code"])) == "VALIDATION_FAILED")
				{
					MessageBoxA(NULL, "Missing log data!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
				}
			}
		}
		catch (const std::exception& ex)
		{
			std::cout << ex.what() << std::endl;
			MessageBoxA(NULL, "Unkown error, contact support!", BlitzWare::API::ApplicationData::name.c_str(), MB_ICONERROR | MB_OK);
		}
	}
}