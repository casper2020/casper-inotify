/**
 * @file api.cc
 *
 * Copyright (c) 2011-2023 Cloudware S.A. All rights reserved.
 *
 * This file is part of casper-inotify.
 *
 * casper-inotify is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * casper-inotify is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with casper. If not, see <http://www.gnu.org/licenses/>.
 */

#include "api.h"

#include <string.h> // strerror

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <assert.h>
#include <syslog.h>

// setgid, setuid, etc 
#include <sys/types.h>
#include <unistd.h>

// getpwnam
#include <sys/types.h>
#include <pwd.h>

// initgroups
#include <grp.h>

// fnmatch
#include <fnmatch.h>

#include "json/json.h"

#include <fstream>
#include <streambuf>
#include <chrono> // std::chrono

#include <signal.h>

// https://man7.org/linux/man-pages/man7/inotify.7.html

const std::map<uint32_t, const casper::inotify::API::FieldInfo> casper::inotify::API::sk_field_id_to_name_map_ {
    { IN_ACCESS       , { "IN_ACCESS"       , "access"       , "File was accessed." } },
    { IN_ATTRIB       , { "IN_ATTRIB"       , "attrib"       , "Metadata, permissions, timestamps, ownership, etc, changes." } },
    
    { IN_CLOSE        , { "IN_CLOSE"        , "close"        , "IN_CLOSE_WRITE | IN_CLOSE_NOWRITE"                           } },
    { IN_CLOSE_WRITE  , { "IN_CLOSE_WRITE"  , "close_write"  , "File opened for writing was closed."                         } },
    { IN_CLOSE_NOWRITE, { "IN_CLOSE_NOWRITE", "close_nowrite", "File or directory not opened for writing was closed."        } },
    
    { IN_CREATE       , { "IN_CREATE"       , "create"       , "File/directory created in watched directory."                } },
    { IN_DELETE       , { "IN_DELETE"       , "delete"       , "File/directory deleted from watched directory."              } },
    { IN_DELETE_SELF  , { "IN_DELETE_SELF"  , "delete_self"  , "Watched file/directory was itself deleted."                  } },
    
    { IN_MODIFY       , { "IN_MODIFY"       , "modify"       , "File was modified."                                          } },
    
    { IN_MOVE         , { "IN_MOVE"         , "move"         , "IN_MOVED_FROM | IN_MOVED_TO."                                } },
    { IN_MOVE_SELF    , { "IN_MOVE_SELF"    , "move_self"    , "Watched file/directory was itself moved."                    } },
    { IN_MOVED_FROM   , { "IN_MOVED_FROM"   , "move_from"    , "Generated for the directory containing the old filename when a file is renamed." } },
    { IN_MOVED_TO     , { "IN_MOVED_TO"     , "move_to"      , "Generated for the directory containing the new filename when a file is renamed." } },
    
    { IN_OPEN         , { "IN_OPEN"         , "open"         , "File or directory was opened."                                                   } }
};

const std::map<std::string, uint32_t> casper::inotify::API::sk_field_key_to_id_map_ = {
    
    { "open"         , IN_OPEN          },
    { "create"       , IN_CREATE        },
    
    { "access"       , IN_ACCESS        },
    { "modify"       , IN_MODIFY        },
    
    { "attrib"       , IN_ATTRIB        },
    
    { "close_write"  , IN_CLOSE_WRITE   },
    { "close_nowrite", IN_CLOSE_NOWRITE },
    { "close"        , IN_CLOSE         },
    
    { "delete"       , IN_DELETE        },
    { "delete_sef"   , IN_DELETE_SELF   },
    
    { "move"         , IN_MOVE          },
    { "move_self"    , IN_MOVE_SELF     },
    { "move_from"    , IN_MOVED_FROM    },
    { "move_to"      , IN_MOVED_TO      }
    
};

#define LOGGER_COLOR_PREFIX "\e"

#define LOGGER_RESET_ATTRS        LOGGER_COLOR_PREFIX "[0m"

#define LOGGER_RESET_ATTRS        LOGGER_COLOR_PREFIX "[0m"

#define LOGGER_MAGENTA_COLOR      LOGGER_COLOR_PREFIX "[00;35m"

#define LOGGER_RED_COLOR          LOGGER_COLOR_PREFIX "[00;31m"
#define LOGGER_LIGHT_RED_COLOR    LOGGER_COLOR_PREFIX "[00;91m"

#define LOGGER_GREEN_COLOR        LOGGER_COLOR_PREFIX "[00;32m"
#define LOGGER_LIGHT_GREEN_COLOR  LOGGER_COLOR_PREFIX "[00;92m"

#define LOGGER_CYAN_COLOR         LOGGER_COLOR_PREFIX "[00;36m"
#define LOGGER_LIGHT_CYAN_COLOR   LOGGER_COLOR_PREFIX "[00;96m"

#define LOGGER_BLUE_COLOR         LOGGER_COLOR_PREFIX "[00;34m"
#define LOGGER_LIGHT_BLUE_COLOR   LOGGER_COLOR_PREFIX "[00;94m"

#define LOGGER_LIGHT_GRAY_COLOR   LOGGER_COLOR_PREFIX "[00;37m"
#define LOGGER_DARK_GRAY_COLOR    LOGGER_COLOR_PREFIX "[00;90m"

#define LOGGER_WHITE_COLOR        LOGGER_COLOR_PREFIX "[00;97m"
#define LOGGER_YELLOW_COLOR       LOGGER_COLOR_PREFIX "[00;33m"
#define LOGGER_ORANGE_COLOR       LOGGER_COLOR_PREFIX "[00;33m"

#define LOGGER_WARNING_COLOR      LOGGER_COLOR_PREFIX "[00;33m"

#define LOGGER_COLOR(a_name)      LOGGER_ ## a_name ## _COLOR

#define LOGGER_PASS_SYMBOL    "✓"
#define LOGGER_FAIL_SYMBOL    "✕"
#define LOGGER_WARNING_SYMBOL "⚠︎"

#define API_DEFAULT_SHELL "/bin/sh"
#define API_DEFAULT_PATH  "/usr/bin:/usr/local/bin"

#define DEBUG_LEVEL_BASIC 1
#define DEBUG_LEVEL_TRACE 2

#define DEBUG_LEVEL 1

#if defined(DEBUG) || defined(_DEBUG) || defined(ENABLE_DEBUG)
    #define IF_DEBUG(a_level, ...) if ( a_level <= DEBUG_LEVEL ) { __VA_ARGS__ }
    #define IF_DEBUG_DECLARE(...) __VA_ARGS__
    #define DEBUG_LOG(a_level, a_format, ...) IF_DEBUG(a_level, Log(API::LogLevel::_Debug, "@ %s: " a_format, __FUNCTION__, __VA_ARGS__);)
#else
    #define IF_DEBUG(a_level, ...)
    #define IF_DEBUG_DECLARE(...)
    #define DEBUG_LOG(a_level, a_format, ...)
#endif

/**
 * @brief Default constructor.
 *
 * @param a_abbtr   Abbreviation.
 * @param a_version Name & version.
 */
casper::inotify::API::API (const char* const a_abbr, const char* const a_info)
: abbr_(a_abbr), info_(a_info)
{
    pid_         = getpid();
    inotify_     = { -1, { 0 } };
    log_         = { nullptr, API::LogLevel::_Event, 0, { 0 } };
    hostname_[0] = '\0';
}

/**
 * @brief Destructor.
 */
casper::inotify::API::~API ()
{
    Unload();
}

// MARK: -

/**
 * @brief Initialize instance.
 *
 * @param a_level One of \link API::LogLevel \link.
 * @param a_uri   Log file URI.
 */
void casper::inotify::API::Init (const LogLevel a_level, const std::string& a_uri)
{
    Unload();
    log_.fp_ = fopen(a_uri.c_str(), "w+");
    if ( nullptr == log_.fp_ ) {
        throw inotify::Exception("An error occurred while trying to open %s: %d - %s", 
            a_uri.c_str(), errno, strerror(errno)
        );
    }
    // ... log ...
    Log(API::LogLevel::_Info, "%s...", "Initialized");
}

/**
 * @brief Load monitoring rules.
 *
 * @param a_uri Configuration file ( JSON ) URI.
 */
void casper::inotify::API::Load (const std::string& a_uri)
{
    const auto events2mask = [] (const Json::Value& a_array) -> uint32_t {
        uint32_t mask = 0;
        for ( Json::ArrayIndex idx = 0 ; idx < a_array.size(); ++idx ) {
            const auto it = sk_field_key_to_id_map_.find(a_array[idx].asString());
            if ( sk_field_key_to_id_map_.end() != it ) {
                mask = mask | it->second;
            } else {
                fprintf(stdout, "%s ???\n", a_array[idx].asCString());
            }
        }
        return mask;
    };
    // ... log ...
    Log(API::LogLevel::_Info, "Loading '%s'...", a_uri.c_str());
    // ... debug log fields ...
    IF_DEBUG(DEBUG_LEVEL_BASIC, {
        const auto spacer = [this]() {
            for ( size_t idx = 0 ; idx < 140 ; ++idx ) {
                fprintf(log_.fp_, "%c", '-');
            }
            fprintf(log_.fp_, "\n");
        };        
        spacer();
        for ( const auto& it : API::sk_field_id_to_name_map_ ) {
            fprintf(log_.fp_, "\t0x%08X - %-16.16s - %-13.13s - %s\n", it.first, it.second.name_, it.second.key_, it.second.description_);
        }
        spacer();
        fflush(stdout);
    })
    // ...
    std::ifstream t(a_uri);
    const std::string data((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());    
    Json::Reader reader;
    Json::Value  obj;
    if ( false == reader.parse(data, obj) ) {
        const auto errors = reader.getStructuredErrors();
        if ( errors.size() > 0 ) {
            throw inotify::Exception("An error ocurred while parsing '%s as JSON': %s!",
                                    data.c_str(), reader.getFormatedErrorMessages().c_str()
            );
        } else {
            throw inotify::Exception("An error ocurred while parsing '%s' as JSON!",
                                    data.c_str()
            );
        }
    }
    // ... set defaults ...
    defaults_.user_ = obj["user"].asString();
    if ( true == obj.isMember("command") ) {
        defaults_.command_ = obj["command"].asString();
    }
    defaults_.message_ = obj.get("message", "CASPER-INOTIFY :: WARNING :: ${CASPER_INOTIFY_NAME} ${CASPER_INOTIFY_OBJECT} was ${CASPER_INOTIFY_EVENT} @ ${CASPER_INOTIFY_HOSTNAME} [ ${CASPER_INOTIFY_DATETIME} ]").asString();
    // ... load entries
    {
        const Json::Value dummy_string = "";
        // ... directories ...
        {
            const Json::Value& dirs = obj.get("directories", Json::Value::null);
            if ( false == dirs.isNull() && dirs.size() > 0 ) {
                for ( Json::ArrayIndex idx = 0 ; idx < dirs.size() ; ++idx ) {
                    const Json::Value& uri = dirs[idx].get("uri", Json::Value::null);
                    if ( true == uri.isNull() ) {
                        continue;
                    }
                    const uint32_t mask = events2mask(dirs[idx].get("events", Json::Value::null)) | IN_ONLYDIR;
                    if ( 0 == mask ) {
                        continue;
                    }
                    Add(API::Type::_Directory, dirs[idx], uri.asString(), mask);
                }
            }
        }
        // ... files ...
        {
            const Json::Value& files = obj.get("files", Json::Value::null);
            if ( false == files.isNull() && files.size() > 0 ) {
                for ( Json::ArrayIndex idx = 0 ; idx < files.size() ; ++idx ) {
                    const Json::Value& uri = files[idx].get("uri", Json::Value::null);
                    if ( true == uri.isNull() ) {
                        continue;
                    }
                    uint32_t mask = events2mask(files[idx].get("events", Json::Value::null));
                    if ( 0 == mask ) {
                        continue;
                    }
                    if ( mask & IN_DELETE ) {
                        mask = mask | IN_DELETE_SELF;
                    }
                    // ... special case(s):
                    if ( mask & IN_MODIFY ) {
                        const std::string tmp = uri.asString();
                        // ... also watch directory ...
                        std::string directory;
                        const size_t last_slash_idx = tmp.rfind('/');
                        if ( std::string::npos != last_slash_idx ) {
                            directory = tmp.substr(0, last_slash_idx);
                        } else {
                            continue;
                        }
                        Add(API::Type::_Directory, files[idx], directory, IN_CREATE,
                                std::bind(&API::Handler, this, std::placeholders::_1, std::placeholders::_2)
                        );
                    }
                    // ...
                    Add(API::Type::_File, files[idx], uri.asString(), mask);
                }
            }
        }
    }    
    // ...
    hostname_[0] = '\0';
    if ( -1 ==  gethostname(hostname_, sizeof(hostname_) / sizeof(hostname_[0])) ) {
        throw inotify::Exception("An error occurred while trying to obtain hostname: %d - %s", errno, strerror(errno));
    }
}

/**
 * @brief Monitor a set of directories and / or files.
 */
int casper::inotify::API::Watch ()
{
    // ... log ...
    Log(API::LogLevel::_Info, "%s...", "Initializing");
    // ... initialize ...
    inotify_.fd_ = inotify_init();
    if ( inotify_.fd_ < 0 ) {
        // ... report error ...
        throw inotify::Exception("An error occurred while initializing library: %d - %s",
                                 errno, strerror(errno)
        );
    }
    // ... log ...
    Log(API::LogLevel::_Info, "%s...", "Registering");
    // ... register & track ...
    log_.entry_ml_ = 0;    
    for ( auto& entry : entries_.all_ ) {
        if ( true == Register(entry) ) {
            Track(entry, true);
        } else {
            Track(entry, false);
        }
        if ( entry->uri_.length() > log_.entry_ml_ ) {
            log_.entry_ml_ = entry->uri_.length();
        }
    }
    // ... log ...
    Log(entries_);
    Log(API::LogLevel::_Info, "%s...", "Ready");
    // ... loop ...
    while ( true ) {
        try {
            // ... log ...
            Log(API::LogLevel::_Debug, "%s...", "Waiting");
            // ... wait for event ...
            Wait();
        } catch (const std::exception& a_e) {
            // ... log and break ...
            try {
                Log(API::LogLevel::_Error, "%s", a_e.what());
            } catch(...) {
                fprintf(stderr, "Exiting due to an exception!");
                break;
            }
        }
    }
    // ... unregister ...
    for ( auto& it : entries_.good_ ) {
        if ( true == Unregister(it.second) ) {
            Untrack(it.second);
        }
    }
    // ... clean up  ...
    Unload();
    // ... done ...
    return 0;
}

// MARK: -

/**
 * @brief Add an entry to watch list.
 *
 * @param a_entry See \link API::Entry \link.
 */
bool casper::inotify::API::Register (API::Entry* a_entry)
{
    a_entry->wd_ = inotify_add_watch(inotify_.fd_, a_entry->uri_.c_str(), a_entry->mask_);
    if ( -1 == a_entry->wd_ ) {
        // ... track error ...
        a_entry->error_ = "An error occurred while registering an event for " + a_entry->uri_ + ": " + std::to_string(errno) + " - " + strerror(errno);
        // ... failed ...
        return false;
    }
    // ... clear error and / or warning ...
    a_entry->error_   = "";
    a_entry->warning_ = "";
    // ... success ...
    return true;
}

/**
 * @brief Remove an entry from watch list.
 *
 * @param a_entry See \link API::Entry \link.
 */
bool casper::inotify::API::Unregister (API::Entry* a_entry)
{
    // ... nothing to unregister?
    if ( -1 == a_entry->wd_ ) {
        // ... done ...
        return true;
    }
    // ... try to remove event ...
    if ( 0 != inotify_rm_watch(inotify_.fd_, a_entry->wd_) ) {
        // ... log ..
        Log(API::LogLevel::_Error, "An error occurred while unregistering event %d ( %s ): %d - %s",
            a_entry->wd_, a_entry->uri_.c_str(), errno, strerror(errno)
        );
        // ... failed ...
        return false;
    }
    // ... untrack ...
    a_entry->wd_ = -1;
    // ... clear error and / or warning ...
    a_entry->error_   = "";
    a_entry->warning_ = "";
    // ... succeded ...
    return true;
}

/**
 * @brief Wait for next event.
 */
void casper::inotify::API::Wait ()
{   
    const int length = read(inotify_.fd_, inotify_.buffer_, IN_BUFFER_MAX_LENGTH);
    if ( length < 0 ) {
        throw inotify::Exception("read error: %d - %s!", errno, strerror(errno));
    }
    
    // ... log ...
    DEBUG_LOG(DEBUG_LEVEL_TRACE, "length = %d", length);
    
    std::vector<std::string> actions;
    int idx = 0;
    while ( idx < length ) {
        // ... grab event ...
        struct inotify_event* event = (struct inotify_event*)&inotify_.buffer_[idx];
        const auto entry = entries_.good_.find(event->wd);
        if ( entries_.good_.end() == entry ) {
            // ... log ...
            DEBUG_LOG(DEBUG_LEVEL_TRACE, "%3d : event triggered, mask = 0x%08X...", idx, event->mask);
            DEBUG_LOG(DEBUG_LEVEL_TRACE, "%s", "event NOT in watch list...");
            // ... next ...
            idx += IN_STRUCT_EVENT_SIZE + event->len;
            continue;
        }
        // ...
        const char* entry_target;
        switch (entry->second->type_) {
            case API::Type::_File:
                entry_target = "file";
                break;
            case API::Type::_Directory:
                entry_target = "directory";
                break;
            default:
                entry_target = "???";
                break;
        }
        // ...
        API::Event e;
        e.mask_             = event->mask;
        e.iso_8601_with_tz_ = Now(log_.time_);
        // When events are generated for objects inside a watched directory,
        // the name field in the returned inotify_event structure identifies
        // the name of the file within the directory.
        e.inside_a_watched_directory_ = ( event->len > 0 );
        if ( true == e.inside_a_watched_directory_ ) {
            // ... event is for an object inside a watched directory ...
            e.object_name_c_str_    = event->name;
            e.parent_object_type_c_ = 'd';
            e.parent_object_name_   = entry->second->uri_.c_str();
        } else {
            // ... event is for an object ....
            e.object_name_c_str_    = entry->second->uri_.c_str();
            e.parent_object_type_c_ = '-';
            e.parent_object_name_   = nullptr;
        }
        // ...
        if ( event->mask & IN_ISDIR ) {
            e.object_type_c_     = 'd';
            e.object_type_c_str_ = "directory";
        } else {
            e.object_type_c_     = 'f';
            e.object_type_c_str_ = "file";
        }
        // ... debug ...
        DEBUG_LOG(DEBUG_LEVEL_TRACE,
                    "%3d : event triggered, wd = %3d, mask = 0x%08X, e.object_name_c_str_ = %s, entry_target = %s, e.object_type_c_str_ = %s, uri = %s...",
                    idx, event->wd, event->mask, e.object_name_c_str_, entry_target, e.object_type_c_str_, entry->second->uri_.c_str()
        );
        // ... filter?
        DEBUG_LOG(DEBUG_LEVEL_TRACE,
                    "%3d : apply filter '%s' over '%s'", idx, entry->second->pattern_.c_str(), e.object_name_c_str_
        )
        if ( 0 != entry->second->pattern_.length() && 0 != fnmatch(entry->second->pattern_.c_str(), e.object_name_c_str_, /* flags */ 0) ) {
            // ... log ...
            DEBUG_LOG(DEBUG_LEVEL_TRACE, "%3d : SKIPPED, no match for pattern %s", idx, entry->second->pattern_.c_str())
            // ... next ...
            idx += IN_STRUCT_EVENT_SIZE + event->len;
            continue;
        }
#if DEBUG
        //
        // when monitoring a directory:
        //
        // the events marked below can occur both for the directory itself and for objects inside the directory:
        //
        // ( IN_ATTRIB, IN_CLOSE_NOWRITE, IN_OPEN )
        if ( ( event->mask & IN_ATTRIB ) || ( event->mask & IN_CLOSE_NOWRITE ) || ( event->mask & IN_OPEN ) ) {
            if ( event->mask & IN_ISDIR ) {
                // TODO
            }
        }
        // ... and ...
        //
        // the events below occur only for objects inside the directory (not for the directory itself).
        //
        // ( IN_ACCESS, IN_CLOSE_WRITE, IN_CREATE, IN_DELETE, IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO )
        if (
            ( event->mask & IN_ACCESS ) || ( event->mask & IN_CREATE ) || ( event->mask & IN_DELETE ) || ( event->mask & IN_MODIFY )
            ||
            ( event->mask & IN_CLOSE_WRITE  )
            ||
            ( event->mask &   IN_MOVED_FROM ) || ( event->mask & IN_MOVED_TO )
            ) {
                // TODO
            }
#endif
        // ...
        if ( event->mask & IN_OPEN ) {
            actions.push_back("open");
        }
        if ( event->mask & IN_CLOSE ) {
            actions.push_back("closed");
        }
        if ( event->mask & IN_ACCESS ) {
            actions.push_back("accessed");
        }
        if ( event->mask & IN_CREATE ) {
            actions.push_back("created");
        }
        if ( event->mask & IN_MODIFY ) {
            actions.push_back("modified");
        }
        if ( event->mask & IN_DELETE || event->mask & IN_DELETE_SELF ) {
            actions.push_back("deleted");
        }
        if ( event->mask & IN_IGNORED ) {
            actions.push_back("ignored");
        }
        //
        if ( 0 != actions.size() ) {
            for ( auto action : actions ) {
                e.name_ += ", " + action;
            }
            e.name_ = std::string(e.name_.c_str() + 2);
        } else {
            e.name_ = "???";
        }
        // ... log ...
        IF_DEBUG(DEBUG_LEVEL_BASIC, { 
            if ( nullptr == entry->second->handler_ ) {
                    Log(DEBUG_LEVEL_BASIC, e, *entry->second, actions); 
                }                
            }
        );
        // ...
        if ( nullptr != entry->second->handler_ && false == entry->second->handler_(*entry->second, e) ) {
            // ... log ...
            DEBUG_LOG(DEBUG_LEVEL_BASIC, "➢ %u, %s, event skipped!", entry->second->wd_, e.name_.c_str());
            // ... next ...
            idx += IN_STRUCT_EVENT_SIZE + event->len;
            continue;
        }
        // ... ignore or launch a process?
        if ( 0 == e.name_.compare("???") || 0 == e.name_.length() ) {
            Ignore(*entry->second, e);
        } else if ( ! ( event->mask & IN_IGNORED ) ) {
            Spawn(*entry->second, e);
        }
        // ... was removed explicitly (inotify_rm_watch(2)) or
        //     automatically (file was deleted, or filesystem was unmounted) ...
        if ( event->mask & IN_IGNORED ) {
            Untrack(entry->second, /* a_reason */ "event was removed explicitly or automatically!", /* a_log */ true);
        }
        // ... clean up ...
        actions.clear();
        // ... next ...
        idx += IN_STRUCT_EVENT_SIZE + event->len;
    }
}

/**
 * @brief Unload monitoring events.
 */
void casper::inotify::API::Unload ()
{
    // ... clean entries ...
    for ( auto& entry : entries_.all_ ) {
        if ( -1 != entry->wd_ ) {
            inotify_rm_watch(inotify_.fd_, entry->wd_);
        }
        delete entry;
    }
    entries_.all_.clear();
    entries_.good_.clear();
    entries_.bad_.clear();
    entries_.uris_.directories_.clear();
    entries_.uris_.files_.clear();
    // ... clean inotify ...
    if ( -1 != inotify_.fd_ ) {
        close(inotify_.fd_);
        inotify_.fd_ = -1;
    }
    // ... close log file ...
    if ( nullptr != log_.fp_ ) {
        fflush(log_.fp_);
        if ( stdout != log_.fp_ ) {
            fclose(log_.fp_);
        }
        log_.fp_ = nullptr;
    }
}

/**
 * @brief Log all entries.
 *
 * @param a_entry Entries to log.
 */
void casper::inotify::API::Log (const API::Entries& a_entries)
{
    // ... log all entries ...
    for ( auto& entry : a_entries.all_ ) {
        if ( -1 != entry->wd_ ) {
            Log(LOGGER_PASS_SYMBOL, *entry);
        } else {
            Log(LOGGER_FAIL_SYMBOL, *entry);
        }
    }
}

/**
 * @brief Log an action trigger for a specific entry.
 *
 * @param a_symbol Symbol to log.
 * @param a_entry  Entry to log.
 */
void casper::inotify::API::Log (const char* const a_symbol, const API::Entry& a_entry)
{
    const std::string log_suffix = 0 != a_entry.pattern_.length() ? ", " + a_entry.pattern_ : "";
    // ...
    char t;
    switch(a_entry.type_) {
        case API::Type::_Directory:
            t = 'd';
            break;
        case API::Type::_File:
            t = 'f';
            break;
        default:
            t = '?';
            break;
    }
    // ...
    if ( -1 != a_entry.wd_ ) {
        Log(API::LogLevel::_Info, " %s [%c] %-*.*s, 0x%08X ⇥ %d%s",
            a_symbol, t, log_.entry_ml_, log_.entry_ml_, a_entry.uri_.c_str(), a_entry.mask_, a_entry.wd_, log_suffix.c_str());
    } else {
        Log(API::LogLevel::_Info, " %s [%c] %-*.*s, 0x%08X ⌁ " LOGGER_FAIL_SYMBOL,
            a_symbol, t, log_.entry_ml_, log_.entry_ml_, a_entry.uri_.c_str(), a_entry.mask_);
        if ( 0 != a_entry.error_.length() ) {
            Log(API::LogLevel::_Error," " LOGGER_FAIL_SYMBOL " %s", a_entry.error_.c_str());
        } else if ( 0 != a_entry.warning_.length() ) {
            Log(API::LogLevel::_Warning," " LOGGER_WARNING_SYMBOL " %s", a_entry.warning_.c_str());
        }
    }
}

/**
 * @brief Log an event trigger for a specific entry.
 *
 * @param a_level   Log level.
 * @param a_entry   Entry to log.
 * @param a_event   Event to log.
 * @param a_actions Actions to log.
 */
void casper::inotify::API::Log (const int a_level,
                                const API::Event& a_event, const API::Entry& a_entry,
                                const std::vector<std::string>& a_actions)
{
    IF_DEBUG(a_level, {
        Log(API::LogLevel::_Debug, "➢ %u, %s", a_entry.wd_, a_entry.uri_.c_str());
        Log(API::LogLevel::_Debug, "➢ 0x%08X, %s @ %s", a_entry.mask_, a_event.object_name_c_str_, a_event.parent_object_name_);
        Log(API::LogLevel::_Debug, "➢ 0x%08X", a_event.mask_);
        for ( auto action : a_actions ) {
            Log(API::LogLevel::_Debug, "    ➢ %s", action.c_str());
        }
    })
}

/**
 * @brief Write a log entry.
 *
 * @param a_level  One of \link API::LogLevel \link.
 * @param a_format fprintf like format.
 * @param ...
 */
void casper::inotify::API::Log (const API::LogLevel a_level, const char* const a_format, ...)
{
    // ... no log?
    if ( nullptr == log_.fp_ || a_level > log_.level_ ) {
        // ... nothing to do here ...
        return;
    }
    // .... log ....
    std::va_list args;
    try {
        const char* what;
        const char* color = LOGGER_RESET_ATTRS;
        switch(a_level) {
            case API::LogLevel::_Info:
                what = "Info";
                break;
            case API::LogLevel::_Warning:
                what = "Warning";
                color = LOGGER_COLOR(YELLOW);
                break;
            case API::LogLevel::_Error:
                what = "Error";
                color = LOGGER_COLOR(RED);
                break;
            case API::LogLevel::_Event:
                what = "Event";
                break;
            case API::LogLevel::_Debug:
                what = "Debug";
                color = LOGGER_COLOR(DARK_GRAY);
                break;
            default:
                what = "???";
                color = LOGGER_COLOR(RED);
                break;
        }
        fprintf(log_.fp_, "%s, %8d, %-10.10s, ", Now(log_.time_), pid_, what);
        {
            auto temp   = std::vector<char> {};
            auto length = std::size_t { 512 };
            while ( temp.size() <= length ) {
                temp.resize(length + 1);
                va_start(args, a_format);
                const auto status = std::vsnprintf(temp.data(), temp.size(), a_format, args);
                va_end(args);
                if ( status < 0 ) {
                    throw std::runtime_error {"string formatting error"};
                }
                length = static_cast<std::size_t>(status);
            }
            fprintf(log_.fp_, "%s%s" LOGGER_RESET_ATTRS, color, length > 0 ? std::string { temp.data(), length }.c_str() : "");
        }
        fprintf(log_.fp_, "\n");
        fflush(log_.fp_);
    } catch (std::exception& a_exception) {
        va_end(args);
        throw a_exception;
    }
}

// MARK: -

/**
 * @brief Add a new entry.
 * 
 * @param a_type    One of \link API::Type \link.
 * @param a_object  JSON object that defines this new entry.
 * @param a_uri     URI for file or directory.
 * @param a_mask    Event mask.
 * @param a_handler Management / special handler.
 */
void casper::inotify::API::Add (const API::Type a_type, const Json::Value& a_object,
                                const std::string& a_uri, uint32_t a_mask,
                                std::function<bool(const struct _Entry&, const Event&)> a_handler)
{
    static const Json::Value dummy_string = Json::Value("");
    // ... set ...
    switch (a_type) {
        case API::Type::_Directory:
            if ( nullptr == a_handler ) {
                entries_.uris_.directories_.insert(a_uri);
            }            
        break;
        case API::Type::_File:
            if ( nullptr == a_handler ) {
                entries_.uris_.files_.insert(a_uri);
            }           
        break; 
        default:
            throw inotify::Exception("Unknown entry type: %u!", (unsigned)a_type);
        break;
    }
    // ... collect ...
    entries_.all_.push_back(new API::Entry{
        /* type_    */ a_type,
        /* uri_     */ a_uri,
        /* mask_    */ a_mask,
        /* wd_      */ -1,
        /* user_    */ a_object.get("user", defaults_.user_).asString(),
        /* cmd_     */ a_object.get("command", defaults_.command_).asString(),
        /* msg_     */ a_object.get("message", defaults_.message_).asString(),
        /* pattern_ */ a_object.get("pattern", dummy_string).asString(),
        /* error_   */ "",
        /* warning_ */ "",
        /* handler_ */ a_handler
    });
}

// MARK: -

/**
 * @brief Call when an entry must be tracked. 
 * 
 * @param a_entry Entry to track.
 * @param a_good  True when it's a good entry.
 * @param a_log   True when a log entry should be created.
 */

void casper::inotify::API::Track (API::Entry* a_entry, const bool a_good, const bool a_log)
{
    if ( true == a_good ) {
        // ... as 'good' entry ...
        entries_.good_[a_entry->wd_] = a_entry;
        // ... log?
        if ( true == a_log ) {
            Log(LOGGER_PASS_SYMBOL, *a_entry);
        }
    } else {
        // ... as 'bad' entry ...
        entries_.bad_.push_back(a_entry);
        // ... log?
        if ( true == a_log ) {
            Log(LOGGER_FAIL_SYMBOL, *a_entry);
        }
    }
}


/**
 * @brief Call when an entry must be untracked. 
 * 
 * @param a_entry  Entry to untrack.
 * @param a_reason Reason for this call.
 * @param a_log    True when a log entry should be created.
 */
void casper::inotify::API::Untrack (API::Entry* a_entry, const char* const a_reason, const bool a_log)
{
    // ... untrack ...
    entries_.good_.erase(entries_.good_.find(a_entry->wd_));
    entries_.bad_.push_back(a_entry);
    a_entry->wd_      = -1;
    a_entry->warning_ = ( nullptr != a_reason ? a_reason : "" );
    // ... log?
    if ( true == a_log ) {
        Log(LOGGER_FAIL_SYMBOL, *a_entry);
    }
}

/**
 * @brief Call when an event was ignored. 
 * 
 * @param a_entry Entry where an event was triggered.
 * @param a_event Event that is being ignored.
 */
void casper::inotify::API::Ignore (const API::Entry& a_entry, const API::Event& a_event)
{
    Log(API::LogLevel::_Event, "[%c%c] %s '%s' was 0x%08X.", 
        a_event.parent_object_type_c_, a_event.object_type_c_, a_event.object_type_c_str_, a_event.object_name_c_str_, a_event.mask_);
    Log(API::LogLevel::_Warning, LOGGER_WARNING_SYMBOL " event ignored!");
}

/**
 * @brief Launch a process for a specific entry / event. 
 * 
 * @param a_entry Entry where an event was triggered.
 * @param a_event Event to process.
 */
void casper::inotify::API::Spawn (const API::Entry& a_entry, const API::Event& a_event)
{
    IF_DEBUG_DECLARE(const char* const sk_dbg_symbol = "➢";)
    // ...
    std::map<const char* const, std::string> vars = {
        { "CASPER_INOTIFY_EVENT"   , a_event.name_              },
        { "CASPER_INOTIFY_OBJECT"  , a_event.object_type_c_str_ },
        { "CASPER_INOTIFY_NAME"    , a_event.object_name_c_str_ },
        { "CASPER_INOTIFY_DATETIME", a_event.iso_8601_with_tz_  },
        { "CASPER_INOTIFY_HOSTNAME", hostname_                  },
        { "CASPER_INOTIFY_MSG"     , a_entry.msg_               },
        { "CASPER_INOTIFY_CMD"     , a_entry.cmd_               }
    };
    // ... debug ...
    IF_DEBUG(DEBUG_LEVEL_BASIC, {
        syslog(LOG_DEBUG, "%s (%s) DBG", sk_dbg_symbol, a_entry.user_.c_str());
        // ... dump env vars ...
        for ( auto it : vars ) {
            syslog(LOG_DEBUG, "    %s VAR %-*.*s: %s", sk_dbg_symbol, 23, 23, it.first, it.second.c_str());
        }
    })
    
    // ...
    std::string cmd, msg;
    const std::map<const std::string*, std::string*> strings = { { &a_entry.cmd_, &cmd}, { &a_entry.msg_, &msg} };
    for ( auto it : strings ) {
        (*it.second) = *it.first;
        for ( auto it2 : vars ) {
            (*it.second) = Replace((*it.second) , ( "${" + std::string(it2.first) + "}" ) , it2.second);
        }
    }
    // ... debug ...
    IF_DEBUG(DEBUG_LEVEL_TRACE, {
        syslog(LOG_DEBUG, "%s (%s) DBG", sk_dbg_symbol, a_entry.user_.c_str());
        // ... dump message?
        if ( a_entry.msg_.length() > 0 ) {
            syslog(LOG_DEBUG, "    %s MSG %s", sk_dbg_symbol, msg.c_str());
        }
        // ... dump command ...
        syslog(LOG_DEBUG, "    %s CMD %s", sk_dbg_symbol, cmd.c_str());
    })
    // ...
    const pid_t pid = fork();
    if ( 0 > pid )  { // ... unable to fork ...
        // ... log ...
        syslog(LOG_ERR, LOGGER_FAIL_SYMBOL " unable to launch %s", cmd.c_str());
        syslog(LOG_ERR, "  ⌃ fork failure!");
        // ... done ...
        return;
    } else if ( 0 == pid ) {  // ... child ...
        // ... close ALL open files ...
        const int max = getdtablesize();
        // ... but skip 0 - stdin, 1 - stdout, 2 - stderr ....
        for ( int n = 3; n < max; n++ ) {
            close(n);
        }
        // ... create session and set process group ID ...
        setsid();
        // ... exec ...
        // TODO CW: confirm this
        signal(SIGINT , SIG_DFL);
        signal(SIGHUP , SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGUSR2, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        // TODO CW: fix this?
        signal(SIGTRAP, SIG_DFL);
        
        typedef struct {
            int         no_;
            std::string str_;
            const char* what_;
        } Error;
        Error error = { 0, "", nullptr };
        
        errno = 0;
        struct passwd* pwd = getpwnam(a_entry.user_.c_str());
        if ( nullptr == pwd ) {
            error.no_   = errno;
            error.str_  = strerror(errno);
            error.what_ = "get user info";
        }
        if ( 0 == error.no_ && 0 != setgid(pwd->pw_gid) ) {
            error.no_   = errno;
            error.str_  = strerror(errno);
            error.what_ = "set effective group ID";
        }
        if ( 0 == error.no_ && 0 != initgroups(a_entry.user_.c_str(), pwd->pw_gid) ) {
            error.no_   = errno;
            error.str_  = strerror(errno);
            error.what_ = "initialize the group access list";
        }
        if ( 0 == error.no_ && 0 != setuid(pwd->pw_uid) ) {
            error.no_   = errno;
            error.str_  = strerror(errno);
            error.what_ = "set the effective user ID";
        }
        if ( 0 == error.no_ && 0 != clearenv() ) {
            error.no_   = -1;
            error.str_  = "";
            error.what_ = "clear environment";
        }
        // ... if not as root ...
        if ( 0 == error.no_ && 0 != pwd->pw_uid ) {
            // ... set specific user environment ...
            if (
                0 != setenv("PATH"              , API_DEFAULT_PATH , 1) ||
                0 != setenv("LOGNAME"           , pwd->pw_name     , 1) ||
                0 != setenv("USER"              , pwd->pw_name     , 1) ||
                0 != setenv("USERNAME"          , pwd->pw_name     , 1) ||
                0 != setenv("HOME"              , pwd->pw_dir      , 1) ||
                0 != setenv("SHELL"             , pwd->pw_shell    , 1)
                ) {
                    error.no_   = -1;
                    error.str_  = "";
                    error.what_ = "set environment";
                }
            // ...
            if ( 0 == error.no_ ) {
                for ( const auto it : vars ) {
                    if ( 0 != setenv(it.first, it.second.c_str(), 1) ) {
                        error.no_   = -1;
                        error.str_  = "";
                        error.what_ = "set environment var";
                        break;
                    }
                }
            }
        }
        // ... error set?
        if ( 0 != error.no_ ) {
            syslog(LOG_ERR, LOGGER_FAIL_SYMBOL " unable to launch %s", cmd.c_str());
            syslog(LOG_ERR, "  ⌃ %s - ( %d ) %s", error.what_, error.no_, error.str_.c_str());
            exit(-1);
        }
        // ...
        (void)execlp(API_DEFAULT_SHELL, API_DEFAULT_SHELL, "-c", cmd.c_str(), nullptr);
        
        // ... if it reaches here, an error occurred with execlp ...
        // ... log ...
        syslog(LOG_ERR, "unable to launch '%s', execlp failed: %d - %s", cmd.c_str(), errno, strerror(errno));
        exit(-1);
        
    } /* else { ... } - parent */
    
    // ... log ...
    syslog(LOG_NOTICE , LOGGER_PASS_SYMBOL " (%s) CMD %s", a_entry.user_.c_str(), cmd.c_str());
}

/**
 * @brief Management / special handler.
 * 
 * @param a_entry Entry where an event was triggered.
 * @param a_event Event that is being ignored.
 */
bool casper::inotify::API::Handler (const API::Entry& a_entry, const API::Event& a_event)
{
    // ... for now, CASE #1 ( see below ) is the only one supported ...
    if ( ! ( ! ( a_event.mask_ & IN_ISDIR ) && ( a_event.mask_ & IN_CREATE ) ) ) {
        // ... rejected ...
        return false;
    }
    //
    // CASE #1:
    //
    // + event is on a directory
    // + a file was created
    // + file needs to be watched ?    
    // ...
    const std::string uri = std::string(a_event.parent_object_name_) + '/' + std::string(a_event.object_name_c_str_);
    if ( entries_.uris_.files_.end() == entries_.uris_.files_.find(uri) ) {
        // ... not applicable ...
        return false;
    }
    // ... log ...
    Log(API::LogLevel::_Info, "Case #1 '%s'...", uri.c_str());
    IF_DEBUG(DEBUG_LEVEL_BASIC, {
            Log(DEBUG_LEVEL_BASIC, a_event, a_entry, { a_event.name_ });
        }             
    )
    // ... search ...
    API::Entry* entry = nullptr;
    for ( size_t idx = 0 ; idx < entries_.bad_.size() ; ++idx ) {
        if ( 0 != entries_.bad_[idx]->uri_.compare(uri) ) {
            continue;
        }
        entry = entries_.bad_[idx];
        entries_.bad_.erase(entries_.bad_.begin() + idx);
        break;
    }
    // ... not found?
    if ( nullptr == entry ) {
        // ... nothing to do here ...
        return false;
    }
    // ... register ...
    if ( true == Register(entry) ) {
        // ... as 'good' entry ...
        Track(entry, true);
        // ... success ...
        return true;
    } else {
        // ... as 'bad' entry ...
        Track(entry, false);
        // ... failure ...
        return false;
    }
}

// MARK: -

/**
 * @brief Replace all occurences of a string.
 * 
 * @param a_value String to process.
 * @param a_from  Value to search for.
 * @param a_to    Value to replace with.
 */
const std::string casper::inotify::API::Replace (std::string a_value, const std::string& a_from, const std::string& a_to)
{
    size_t start_pos = 0;
    while ( std::string::npos != ( start_pos = a_value.find(a_from, start_pos) ) ) {
        a_value.replace(start_pos, a_from.length(), a_to);
        start_pos += a_to.length();
    }
    return a_value;
}

/**
 * @brief Collect current date and time in ISO8601WithTZ format.
 *
 * @param a_buffer Pre-allocated buffer to use.
 */
const char* const casper::inotify::API::Now (char* a_buffer) const
{    
    const auto now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    
    time_t tt     = (time_t)now;
    tm     utc_tm;
    
    if ( &utc_tm != gmtime_r(&tt, &utc_tm) ) {
        throw inotify::Exception("Unable to convert epoch to human readable time!");
    }
    
    const auto seconds = static_cast<uint8_t >(utc_tm.tm_sec        ); /* seconds after the minute [0-60] */
    const auto minutes = static_cast<uint8_t >(utc_tm.tm_min        ); /* minutes after the hour [0-59]   */
    const auto hours   = static_cast<uint8_t >(utc_tm.tm_hour       ); /* hours since midnight [0-23]     */
    const auto day     = static_cast<uint8_t >(utc_tm.tm_mday       ); /* day of the month [1-31]         */
    const auto month   = static_cast<uint8_t >(utc_tm.tm_mon  +    1); /* months since January [1-12]     */
    const auto year    = static_cast<uint16_t>(utc_tm.tm_year + 1900); /* years since 1970...2038         */
    
    const int w = snprintf(a_buffer, 26, "%04u-%02u-%02uT%02u:%02u:%02u+%02u:%02u",
                           year,month, day, hours, minutes, seconds,
                           0, 0
    );
    
    if ( w <=0 || w > 25 ) {
        throw inotify::Exception("Unable to convert epoch to ISO8601WithTZ!");
    }
    
    return a_buffer;
}