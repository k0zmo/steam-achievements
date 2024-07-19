#include <Windows.h>
#include <exception>
#include <iterator>
#include <libloaderapi.h>
#include <synchapi.h>

#include <isteamclient.h>
#include <isteamutils.h>
#include <isteamuser.h>
#include <isteamuserstats.h>
#include <isteamapps.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <ranges>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <stdexcept>

#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace std {

template <>
struct default_delete<HMODULE>
{
    using pointer = HMODULE;
    void operator()(pointer p)
    {
        if (p)
            ::FreeLibrary(p);
    }
};

} // namespace std

namespace utils {

std::optional<std::string> get_string_reg_key(HKEY hKey, const char* value_name)
{
    std::optional<std::string> ret;
    CHAR buf[512];
    DWORD buffer_size = sizeof(buf);
    const ULONG err = ::RegQueryValueExA(hKey, value_name, 0, nullptr, reinterpret_cast<BYTE*>(buf),
                                         &buffer_size);
    if (err == ERROR_SUCCESS)
        ret = buf;
    return ret;
}

std::optional<std::string> get_steam_install_path()
{
    std::optional<std::string> ret;
    HKEY hKey;
    if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Valve\\Steam", 0, KEY_READ | KEY_WOW64_32KEY,
                        &hKey) == ERROR_SUCCESS)
    {
        ret = get_string_reg_key(hKey, "InstallPath");
        ::RegCloseKey(hKey);
    }
    return ret;
}

class dll_query
{
public:
    explicit dll_query(HMODULE mod) : mod_{mod} {}

    template <typename Fun>
    dll_query& get(Fun& fun, const char* fun_name)
    {
        fun = reinterpret_cast<Fun>(GetProcAddress(mod_, fun_name));
        if (!fun)
            throw std::runtime_error{std::format("Couldn't find procedure {}", fun_name)};
        return *this;
    }

private:
    HMODULE mod_;
};

bool iequals(std::string_view a, std::string_view b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) ==
                      std::tolower(static_cast<unsigned char>(b));
           });
}

template <typename T>
std::optional<T> from_string(std::string_view str) noexcept
{
    T result;
    const auto convresult = std::from_chars(str.data(), str.data() + str.length(), result);
    if (convresult.ec == std::errc{} && convresult.ptr == str.data() + str.length())
        return result;
    return std::nullopt;
}

} // namespace utils

namespace steam {

#pragma pack(1)
struct callback_message
{
    int user;
    int id;
    void* param_data;
    int param_size;
};

struct pipe_releaser
{
    ~pipe_releaser()
    {
        if (!pipe_)
            client_.BReleaseSteamPipe(pipe_);
    }

    HSteamPipe pipe_;
    ISteamClient& client_;
};

struct user_releaser
{
    ~user_releaser()
    {
        if (!user_)
            client_.ReleaseUser(pipe_, user_);
    }

    HSteamPipe pipe_;
    HSteamUser user_;
    ISteamClient& client_;
};

enum keyvalue_type : std::uint8_t
{
    none,
    string,
    int32,
    float32,
    pointer,
    wide_string,
    color,
    uint64,
    end,
};

struct keyvalue
{
    static keyvalue invalid;
    keyvalue_type type = keyvalue_type::end;
    std::string name;
    std::variant<std::monostate, std::string, int, float, void*, std::wstring, uint64_t> value;
    std::vector<std::unique_ptr<keyvalue>> sons;

    bool is_valid() const { return !name.empty() && type != keyvalue_type::end; }

    const std::string& as_string() const { return std::get<std::string>(value); }

    const std::string& as_optional_string() const
    {
        if (std::holds_alternative<std::string>(value))
        {
            return as_string();
        }
        else
        {
            static std::string empty;
            return empty;
        }
    }

    int as_int() const
    {
        if (std::holds_alternative<std::string>(value))
        {
            const auto& str = std::get<std::string>(value);
            return utils::from_string<int>(str).value_or(0);
        }
        else
        {
            return std::get<int>(value);
        }
    }

    int as_optional_int(int def_value = 0) const
    {
        if (!is_valid())
            return def_value;
        return as_int();
    }

    float as_float() const
    {
        if (std::holds_alternative<std::string>(value))
        {
            const auto& str = std::get<std::string>(value);
            return utils::from_string<float>(str).value_or(0.f);
        }
        else
        {
            return std::get<float>(value);
        }
    }

    float as_optional_float(float def_value = 0.f) const
    {
        if (!is_valid())
            return def_value;
        return as_float();
    }

    const keyvalue& get(std::string_view in_name) const
    {
        if (sons.empty())
            return invalid;

        const auto it = std::ranges::find_if(
            sons, [in_name](const auto& item) { return utils::iequals(item->name, in_name); });
        if (it == sons.end())
            return invalid;
        return **it;
    }

    const keyvalue& operator[](std::string_view in_name) const { return get(in_name); }
};

keyvalue keyvalue::invalid;

std::string read_null_terminated_string(std::istream& is)
{
    std::string str;
    char c = 0;
    while (is.good())
    {
        is.read(&c, sizeof(c));
        if (c)
            str += c;
        else
            break;
    }
    return str;
}

void read_from_binary_impl(std::istream& is, keyvalue& kv)
{
    while (true)
    {
        steam::keyvalue_type type;
        is.read(reinterpret_cast<char*>(&type), sizeof(type));

        if (type == steam::keyvalue_type::end)
            break;

        auto current = std::make_unique<steam::keyvalue>(type, read_null_terminated_string(is));

        switch (type)
        {
        case steam::keyvalue_type::none:
            read_from_binary_impl(is, *current);
            break;

        case steam::keyvalue_type::string:
            current->value = read_null_terminated_string(is);
            break;

        case steam::keyvalue_type::int32: {
            int value;
            is.read(reinterpret_cast<char*>(&value), sizeof(value));
            current->value = value;
            break;
        }

        default:
            throw std::runtime_error{"not implemented!"};
            break;
        }

        kv.sons.push_back(std::move(current));
    }
}

std::unique_ptr<keyvalue> read_from_binary(std::istream& is)
{
    auto ret = std::make_unique<keyvalue>(steam::keyvalue_type::none, "<root>");
    read_from_binary_impl(is, *ret);
    return ret;
}

enum class stat_type
{
    integer = 1,
    floating_point = 2,
    avg_rate = 3,
    achievement = 4,
    group_achievement = 5
};

struct achievement_def
{
    std::string name;
    std::string description;
    std::string icon_normal;
    std::string icon_locked;
    std::string underlying_stat;
    int stat_min{};
    int stat_max{};
    bool is_hidden{};
};

struct achievement
{
    std::string id;
    std::chrono::utc_clock::time_point unlock_time;
    bool is_achieved{};
};

template <typename T>
struct stat_def
{
    std::string description;
    T min{};
    T max{};
    T max_change{};
    T default_value{};
    bool increment_only{};
};

using integer_stat_def = stat_def<int>;
using float_stat_def = stat_def<float>;

template <typename T>
struct stat
{
    std::string id;
    T value{};
};

using integer_stat = stat<int>;
using float_stat = stat<float>;

struct game_stats_schema
{
    std::string game_name;
    std::map<std::string, steam::achievement_def> achievements;
    std::map<std::string, steam::integer_stat_def> integer_stats;
    std::map<std::string, steam::float_stat_def> float_stats;
};

std::optional<game_stats_schema> load_game_stats_schema(uint32 app_id, std::string_view lang)
{
    std::optional<game_stats_schema> result;
    std::filesystem::path p{utils::get_steam_install_path().value()};
    p /= "appcache";
    p /= "stats";
    p /= std::format("UserGameStatsSchema_{}.bin", app_id);

    std::fstream file(p, std::ios::binary | std::ios::in);
    if (!file.is_open())
        return result;
    auto kv = steam::read_from_binary(file);

    auto& stats = (*kv)[std::to_string(app_id)]["stats"];
    if (!stats.is_valid() || stats.sons.empty())
        return result;

    result.emplace();

    auto& gamename = (*kv)[std::to_string(app_id)]["gamename"];
    if (gamename.is_valid())
        result->game_name = gamename.as_string();

    auto get_localized_string = [](const keyvalue& node, std::string_view lang,
                                   std::string_view fallback_lang = "english") {
        const auto& localized = node[lang];
        if (localized.is_valid())
            return localized.as_string();
        const auto& fallback = node[fallback_lang];
        if (fallback.is_valid())
            return fallback.as_string();
        return std::string{};
    };

    for (const auto& stat : stats.sons)
    {
        if (stat->type == steam::keyvalue_type::none && !stat->sons.empty())
        {
            // Why they are grouped?
            const auto& type_int = (*stat)["type_int"];
            const stat_type type{type_int.is_valid() ? type_int.as_int()
                                                     : (*stat)["type"].as_int()};

            if (type == stat_type::achievement || type == stat_type::group_achievement)
            {
                for (const auto& bit : (*stat)["bits"].sons)
                {
                    try
                    {
                        const auto name = bit->get("name").as_string();
                        const auto& display = (*bit)["display"];
                        result->achievements.try_emplace(
                            name, steam::achievement_def{
                                      .name = get_localized_string(display["name"], lang),
                                      .description = get_localized_string(display["desc"], lang),
                                      .icon_normal = display["icon"].as_optional_string(),
                                      .icon_locked = display["icon_gray"].as_optional_string(),
                                      .is_hidden = display["hidden"].as_string() == "1"});

                        const auto& progress = bit->get("progress");
                        if (progress.is_valid())
                        {
                            if (progress["value"]["operation"].as_string() == "statvalue")
                            {
                                auto& def = result->achievements[name];
                                def.underlying_stat = progress["value"]["operand1"].as_string();
                                def.stat_min = progress["min_val"].as_int();
                                def.stat_max = progress["max_val"].as_int();
                            }
                            else
                            {
                                throw std::runtime_error{"not yet implemented"};
                            }
                        }
                    }
                    catch (const std::bad_variant_access&)
                    {
                        continue;
                    }
                }
            }
            else if (type == stat_type::integer)
            {
                try
                {
                    result->integer_stats.try_emplace(
                        stat->get("name").as_string(),
                        steam::integer_stat_def{
                            .description = stat->get("display")["name"].as_string(),
                            .min = stat->get("min").as_optional_int(),
                            .max = stat->get("max").as_optional_int(),
                            .max_change = stat->get("maxchange").as_optional_int(),
                            .default_value = stat->get("default").as_optional_int(),
                            .increment_only = stat->get("incrementonly").as_optional_int() != 0});
                }
                catch (const std::bad_variant_access&)
                {
                    continue;
                }
            }
            else if (type == stat_type::floating_point || type == stat_type::avg_rate)
            {
                try
                {
                    result->float_stats.try_emplace(
                        stat->get("name").as_string(),
                        steam::float_stat_def{
                            .description = stat->get("display")["name"].as_string(),
                            .min = stat->get("min").as_optional_float(),
                            .max = stat->get("max").as_optional_float(),
                            .max_change = stat->get("maxchange").as_optional_float(),
                            .default_value = stat->get("default").as_optional_float(),
                            .increment_only = stat->get("incrementonly").as_optional_float() != 0});
                }
                catch (const std::bad_variant_access&)
                {
                    continue;
                }
            }
            else
            {
                throw std::runtime_error{"not implemented yet"};
            }
        }
    }

    return result;
}

} // namespace steam

void* (*CreateInterface)(const char*, void*);
bool (*Steam_BGetCallback)(HSteamPipe, steam::callback_message*, int*);
bool (*Steam_FreeLastCallback)(HSteamPipe);

class steam_achievement_query
{
public:
    explicit steam_achievement_query(uint32 app_id) : app_id_{app_id}
    {
        connect_to_steam();
        retrieve_steam_interfaces();

        if (app_id_ != 0 && app_id_ != utils_->GetAppID())
            throw std::runtime_error{"AppId mismatch"};
    }

    steam_achievement_query(const steam_achievement_query&) = delete;
    steam_achievement_query& operator=(const steam_achievement_query&) = delete;

    void start()
    {
        user_stats_->RequestCurrentStats();

        steam::callback_message msg;
        int call;

        bool done = false;

        while (!done)
        {
            while (Steam_BGetCallback(pipe_, &msg, &call))
            {
                switch (msg.id)
                {
                case UserStatsReceived_t::k_iCallback:
                    user_stats_received(*reinterpret_cast<UserStatsReceived_t*>(msg.param_data));
                    print_stats();
                    done = true;
                    break;
                }
                Steam_FreeLastCallback(pipe_);
            }

            Sleep(500);
        }
    }

private:
    void print_stats()
    {
        std::cout << std::format("Achievements ({:>3})\n==================\n\n",
                                 achievements_.size());

        std::string buf;

        for (const auto& achievement : achievements_)
        {
            const auto& def = schema_.achievements.at(achievement.id);
            std::format_to(std::back_inserter(buf), "{:<40} {:<80} {}", def.name, def.description,
                           achievement.is_achieved);
            if (achievement.is_achieved)
                std::format_to(std::back_inserter(buf), " ({})", achievement.unlock_time);
            std::cout << buf << '\n';
            buf.clear();
        }

        std::cout << std::format("\nStatistics ({:>3})\n================\n\n",
                                 integer_stats_.size());

        for (const auto& stat : integer_stats_)
        {
            // const auto& def = schema_.integer_stats.at(stat.id);
            std::cout << std::format("{:<50} {}\n", stat.id, stat.value);
        }
        for (const auto& stat : float_stats_)
        {
            // const auto& def = schema_.float_stats.at(stat.id);
            std::cout << std::format("{:<50} {}f\n", stat.id, stat.value);
        }
    }

private:
    void connect_to_steam()
    {
        client_ = reinterpret_cast<ISteamClient*>(
            CreateInterface(STEAMCLIENT_INTERFACE_VERSION, nullptr));
        if (!client_)
            throw std::runtime_error{"Couldn't create IStreamClient"};

        pipe_ = client_->CreateSteamPipe();
        if (!pipe_)
            throw std::runtime_error{"Couldn't create a steam pipe"};
        pipe_releaser_.emplace(pipe_, *client_);

        userh_ = client_->ConnectToGlobalUser(pipe_);
        if (!userh_)
            throw std::runtime_error{"Couldn't connect to global user"};
        userh_releaser_.emplace(pipe_, userh_, *client_);
    }

    void retrieve_steam_interfaces()
    {
        utils_ = reinterpret_cast<ISteamUtils*>(
            client_->GetISteamUtils(pipe_, STEAMUTILS_INTERFACE_VERSION));
        if (!utils_)
            throw std::runtime_error{"Couldn't get ISteamUtils"};
        user_ = reinterpret_cast<ISteamUser*>(
            client_->GetISteamUser(userh_, pipe_, STEAMUSER_INTERFACE_VERSION));
        if (!user_)
            throw std::runtime_error{"Couldn't get ISteamUser"};
        user_stats_ = reinterpret_cast<ISteamUserStats*>(
            client_->GetISteamUserStats(userh_, pipe_, STEAMUSERSTATS_INTERFACE_VERSION));
        if (!user_stats_)
            throw std::runtime_error{"Couldn't get ISteamUserStats"};
        apps_ = reinterpret_cast<ISteamApps*>(
            client_->GetISteamApps(userh_, pipe_, STEAMAPPS_INTERFACE_VERSION));
        if (!apps_)
            throw std::runtime_error{"Couldn't get ISteamApps"};
    }

    void user_stats_received(const UserStatsReceived_t& msg)
    {
        if (msg.m_eResult != k_EResultOK)
        {
            std::cerr << std::format("Error while retrieving stats: {}\n", (int)msg.m_eResult);
            return;
        }

        auto schema = steam::load_game_stats_schema(app_id_, apps_->GetCurrentGameLanguage());
        if (!schema)
        {
            std::cerr << std::format("Failed to load schema\n");
            return;
        }

        schema_ = *std::move(schema);

        for (const auto& [id, def] : schema_.achievements)
        {
            bool is_achieved = false;
            uint32 unlock_time = 0; // in seconds
            if (!user_stats_->GetAchievementAndUnlockTime(id.c_str(), &is_achieved, &unlock_time))
                continue; // bad id?

            achievements_.push_back(steam::achievement{
                .id = id,
                .unlock_time =
                    std::chrono::utc_clock::time_point(std::chrono::seconds{unlock_time}),
                .is_achieved = is_achieved});
        }

        for (const auto& [id, def] : schema_.integer_stats)
        {
            int32 value;
            if (!user_stats_->GetStat(id.c_str(), &value))
                continue;

            integer_stats_.push_back(steam::integer_stat{.id = id, .value = value});
        }

        for (const auto& [id, def] : schema_.float_stats)
        {
            float value;
            if (!user_stats_->GetStat(id.c_str(), &value))
                continue;

            float_stats_.push_back(steam::float_stat{.id = id, .value = value});
        }
    }

private:
    uint32 app_id_;
    ISteamClient* client_;

    HSteamPipe pipe_;
    std::optional<steam::pipe_releaser> pipe_releaser_;

    HSteamUser userh_;
    std::optional<steam::user_releaser> userh_releaser_;

    ISteamUtils* utils_;
    ISteamUser* user_;
    ISteamUserStats* user_stats_;
    ISteamApps* apps_;

    steam::game_stats_schema schema_;
    std::vector<steam::achievement> achievements_;
    std::vector<steam::integer_stat> integer_stats_;
    std::vector<steam::float_stat> float_stats_;
};

// inline auto constexpr steam_app_id = 1954200; // kena
// inline auto constexpr steam_app_id = 1145360; // hades
inline auto constexpr steam_app_id = 548430; // deep rock
// inline auto constexpr steam_app_id = 1069030; // earthx

int main()
try
{
    // Get Steam installation path
    const auto steam_path_opt = utils::get_steam_install_path();
    if (!steam_path_opt)
        return -1;

#if 1
    auto schema = steam::load_game_stats_schema(steam_app_id, "english");

    if (schema)
    {
        for (const auto& [k, v] : schema->achievements)
        {
            if (v.underlying_stat.empty())
                continue;

            std::cout << std::format("{} ({}) [{}-{}]: {}\n", v.name, v.description, v.stat_min,
                                     v.stat_max, v.underlying_stat);
        }
    }
#elif 1
    namespace fs = std::filesystem;

    for (const auto& entry :
         fs::directory_iterator{fs::path{*steam_path_opt} / "appcache" / "stats"})
    {
        const auto name = entry.path().filename().string();
        if (name.starts_with("UserGameStatsSchema_") && name.ends_with(".bin"))
        {
            constexpr auto prefix_len = std::string_view{"UserGameStatsSchema_"}.length();
            constexpr auto suffix_len = std::string_view{".bin"}.length();

            const auto app_id_str = name.substr(prefix_len, name.size() - prefix_len - suffix_len);
            if (auto app_id = utils::from_string<uint32>(app_id_str))
            {
                auto schema = steam::load_game_stats_schema(*app_id, "english");
                std::cout << std::format("schema: {} {}\n", *app_id, schema.value().game_name);
            }
        }
    }
#else
    // Set this for steamclient - it's needed when steamclient64.dll is loaded into the process
    ::SetEnvironmentVariableA("SteamAppId", std::to_string(0).c_str());

    // Load steamclient
    std::filesystem::path steam_path{*steam_path_opt};
    const auto dll_directory =
        std::format("{};{}", steam_path.string(), (steam_path / "bin").string());
    ::SetDllDirectoryA(dll_directory.c_str());
    std::unique_ptr<HMODULE> steamclient_lib{
        ::LoadLibraryExA((steam_path / "steamclient64.dll").string().c_str(), nullptr,
                         LOAD_WITH_ALTERED_SEARCH_PATH)};
    if (!steamclient_lib)
        throw std::runtime_error{"Couldn't load steamclient64.dll"};

    utils::dll_query{steamclient_lib.get()} //
        .get(CreateInterface, "CreateInterface")
        .get(Steam_BGetCallback, "Steam_BGetCallback")
        .get(Steam_FreeLastCallback, "Steam_FreeLastCallback");

    steam_achievement_query query{0};
    query.start();
#endif
}
catch (const std::exception& ex)
{
    std::cout << "Error: " << ex.what() << std::endl;
}