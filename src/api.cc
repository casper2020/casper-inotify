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

#include <sys/inotify.h>
#include <limits.h>
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

#include "json/json.h"

#include <fstream>
#include <streambuf>
#include <chrono> // std::chrono
#include <functional>

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

#define API_DEFAULT_SHELL "/bin/sh"
#define API_DEFAULT_PATH  "/usr/bin:/usr/local/bin"

/**
 * @brief Default constructor.
 * 
 * @param a_abbtr   Abbreviation.
 * @param a_version Name & version.
 */
casper::inotify::API::API (const char* const a_abbr, const char* const a_info)
: pid_(getpid()), abbr_(a_abbr), info_(a_info)
{
  log_out_fd_ = stdout;
  inotify_fd_ = -1;
  hostname_[0] = '\0';
}

/**
 * @brief Destructor.
 */
casper::inotify::API::~API ()
{
  if ( nullptr != log_out_fd_ ) {
    fflush(log_out_fd_);
    if ( stdout != log_out_fd_ ) {
      fclose(log_out_fd_);
    }
  }
  Unload();
}

/**
 * @brief Load monitoring rules.
 * 
 * @param a_uri Configuration file ( JSON ) URI.
 */
 int casper::inotify::API::Load (const std::string& a_uri)
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
  Log(log_out_fd_, API::What::Info, "Loading '%s'...", a_uri.c_str());
  //
  DumpFields(stdout);
  // ... TODO ...
  try {
    
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
    // ...
    defaults_.user_    = obj["user"].asString();
    if ( true == obj.isMember("command") ) {
      defaults_.command_ = obj["command"].asString();
    }
    defaults_.message_ = obj.get("message", "§.object §.event event triggered for §.name - §.datetime @ §.hostname").asString();
    // ...
    const Json::Value dummy_string = "";
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
	  entries_.vector_.push_back(API::NewEntry(API::Kind::Directory, uri.asString(), mask, dirs[idx], /* a_f_only_ */ false));
	  sets_.directories_.insert(uri.asString());
	}
      }
    }
    // ...
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
	    entries_.vector_.push_back(API::NewEntry(API::Kind::Directory, directory, IN_MODIFY, files[idx], /* f_only_ */ true));
	    if ( IN_MODIFY == mask ) {
	      // TODO: avoid this event?
	    }
	  }
	  // ...
	  entries_.vector_.push_back(API::NewEntry(API::Kind::File, uri.asString(),  mask, files[idx], /* f_only_ */ false));
	  sets_.files_.insert(uri.asString());
	}
      }
    }
    // ...
    hostname_[0] = '\0';
    if ( -1 ==  gethostname(hostname_, sizeof(hostname_) / sizeof(hostname_[0])) ) {
      throw inotify::Exception("An error occurred while trying to obtain hostname: %d - %s", errno, strerror(errno));
    }
  } catch (const Json::Exception& a_json_exception ) {
    throw inotify::Exception("%s",
			     a_json_exception.what()
    );
  }
  // ... done ...
  return 0;
 }

/**
 * @brief Monitor a set of directoriesand / or files.
 */
 int casper::inotify::API::Watch ()
 {
   // ... log ...
   Log(log_out_fd_, API::What::Info, "%s...", "Initializing");
   // ... initialize ...
   inotify_fd_ = inotify_init();
   if ( inotify_fd_ < 0 ) {
     // ... report error ...
     throw inotify::Exception("An error occurred while initializing library: %d - %s",
			      errno, strerror(errno)
     );
     // ... done ...
     return -1;
   }
   // ... register ...
   Log(log_out_fd_, API::What::Info, "%s...", "Registering");
   size_t ml = 0;
   for ( auto& entry : entries_.vector_ ) {
     entry->wd_ = inotify_add_watch(inotify_fd_, entry->uri_.c_str(), entry->mask_);
     if ( -1 == entry->wd_ ) {
       // ... report error ...
       entry->err_ = "An error occurred while registering an event for " + entry->uri_ + ": " + std::to_string(errno) + " - " + strerror(errno);
     } else {
       // ... track ...
       entries_.map_[entry->wd_] = entry;
     }
     if ( entry->uri_.length() > ml ) {
       ml = entry->uri_.length();
     }
   }
   // ... log ...
   for ( auto& entry : entries_.vector_ ) {
       char t;
       switch(entry->kind_) {
       case API::Kind::Directory:
	 t = 'd';
	 break;
       case API::Kind::File:
	 t = 'f';
	 break;
       default:
	 t = '?';
	 break;
       }
       // ... log ...
       if ( -1 != entry->wd_ ) {
	 Log(log_out_fd_, API::What::Info, " ✓ [%c] %-*.*s, 0x%08X ⇥ %d", t, int(ml), int(ml), entry->uri_.c_str(), entry->mask_, entry->wd_);
       } else {
	 Log(log_out_fd_, API::What::Info, " ⨯ [%c] %-*.*s, 0x%08X ⌁ ⨯", t, int(ml), int(ml), entry->uri_.c_str(), entry->mask_);
	 Log(log_out_fd_, API::What::Error," ⨯ %s", entry->err_.c_str());
       }
   }
   // ... loop ...
   while ( 1 /* TODO */ ) {
     try {
       // ... log ...
       Log(log_out_fd_, API::What::Info, "Waiting...");
       // ... wait for event ...
       Wait();
     } catch (const std::exception& a_e) {
       try {
	 Log(log_out_fd_, API::What::Info, "%s", a_e.what());
       } catch(...) {
	 fprintf(stderr, "Exiting due to exception!");
       }
     }

    }
   // ... unregister ...
   for ( auto& entry : entries_.vector_ ) {
     if ( -1 != entry->wd_ ) {
       if ( 0 != inotify_rm_watch(inotify_fd_, entry->wd_) ) {
	 Log(log_out_fd_, API::What::Error, "An error occurred while unregistering event %d ( %s ): %d - %s", 
	     entry->wd_, entry->uri_.c_str(), errno, strerror(errno)
	 );
       } else {
	 entries_.map_.erase(entries_.map_.find(entry->wd_));
	 entry->wd_ = -1;
       }
     }
   }
    // ... clean up  ...
   Unload();
   // ... done ...    
   return 0;
 }

 // MARK: -

#define MAX_EVENTS 1024 /* Max. number of events to process at one go*/
#define LEN_NAME 1024   /* Assuming length of the filename won't exceed 16 bytes*/
#define EVENT_SIZE  ( sizeof (struct inotify_event) ) /*size of one event*/
#define BUF_LEN     ( MAX_EVENTS * ( EVENT_SIZE + LEN_NAME )) /*buffer to store the data of events*/

void casper::inotify::API::Wait () {
  
  char buffer[BUF_LEN];
  int length, i = 0;
  
  length = read(inotify_fd_, buffer, BUF_LEN);
  if ( length < 0 ) {
    // ... report ...
    throw inotify::Exception("read error: %d - %s!", errno, strerror(errno));
  }

  // ... log ...
  Log(log_out_fd_, API::What::Debug, "@ %s - length = %d", __FUNCTION__, length);

  // ... sanity check ...
  assert(0 == tmp_was_deleted_.size());

  std::vector<std::string> actions;
  while ( i < length ) {
    // ... grab event ...
    struct inotify_event* event = (struct inotify_event*)&buffer[i];
    const auto entry = entries_.map_.find(event->wd);
    if ( entries_.map_.end() == entry ) {
      // ... log ...
      Log(log_out_fd_, API::What::Debug, "@ %s - %3d : event triggered, mask = 0x%08X...", __FUNCTION__, i, event->mask);
      Log(log_out_fd_, API::What::Debug, "@ %s - event NOT in watch list...", __FUNCTION__);
      // ... next ...
      i += EVENT_SIZE + event->len;
      continue;
    }
    // ...
    const char* entry_target;
    switch (entry->second->kind_) {
    case File:
      entry_target = "file";
      break;
    case Directory:
      entry_target = "directory";
      break;
    default:
      entry_target = "???";
      break;
    }
    // ...
    API::E e;
    e.iso_8601_with_tz_ = NowISO8601WithTZ();
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
    // ... and log ...
    Log(log_out_fd_, API::What::Debug, "@ %s - %3d : event triggered, mask = 0x%08X, e.object_name_c_str_ = %s, entry_target = %s, e.object_type_c_str_ = %s, uri = %s...",
	__FUNCTION__, i, event->mask, e.object_name_c_str_, entry_target, e.object_type_c_str_, entry->second->uri_.c_str()
    );

    //
    // when monitoring a directory:
    //
    // the events marked below can occur both for the directory itself and for objects inside the directory:
    //
    // ( IN_ATTRIB, IN_CLOSE_NOWRITE, IN_OPEN )
    if ( ( event->mask & IN_ATTRIB ) || ( event->mask & IN_CLOSE_NOWRITE ) || ( event->mask & IN_OPEN ) ) {
      if ( event->mask & IN_ISDIR ) {
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
    
    }
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
    // TODO: handle with IN_IGNORED event and remove from watch
    if ( event->mask & IN_DELETE ) {
      actions.push_back("deleted");
    }
    if ( event-> mask & IN_DELETE_SELF ) {
      actions.push_back("deleted");
    }
    if ( ( event->mask & IN_DELETE ) || ( event-> mask & IN_DELETE_SELF ) ) {
      tmp_was_deleted_.push_back(entry->second);
    }
    // ... log ...
    if ( 0 == actions.size() ) {
	Log(log_out_fd_, API::What::Event, "[%c%c] %s '%s' was 0x%08X.", e.parent_object_type_c_, e.object_type_c_, e.object_type_c_str_, e.object_name_c_str_, event->mask);
	Log(log_out_fd_, API::What::Warning, "event ignored!");
    } else {
      for ( auto action : actions ) {
	Log(log_out_fd_, API::What::Event, "[%c%c] %s '%s' was %s.", e.parent_object_type_c_, e.object_type_c_, e.object_type_c_str_, e.object_name_c_str_, action.c_str());
      }
      e.name_ = actions[0].c_str();
      if ( 0 != entry->second->cmd_.length() ) {
	Spawn(*entry->second, e);	
      } else {
	Log(log_out_fd_, API::What::Warning, "event ignored!");
      }
    }
    // ... clean up ...
    actions.clear();
    // ... next ...
    i += EVENT_SIZE + event->len;
  }
  // TODO: handle with tmp_was_deleted_
  Log(log_out_fd_, API::What::Debug, "@ %s - deleted %zu event(s)", __FUNCTION__, tmp_was_deleted_.size());
  tmp_was_deleted_.clear();
}

/**
 * @brief Unload monitoring events.
 */
 void casper::inotify::API::Unload ()
 {
   // ... anything to load?
   if ( -1 == inotify_fd_ ) {
     // ... no ...
     return;
   }
   // ... clean entries ...
   for ( auto& entry : entries_.vector_ ) {
     if ( -1 != entry->wd_ ) {
       inotify_rm_watch(inotify_fd_, entry->wd_);
     }
     delete entry;
   }
   entries_.vector_.clear();
   entries_.map_.clear();
   sets_.directories_.clear();
   sets_.files_.clear();
   // ... clean inotify ...
   close(inotify_fd_);    
   inotify_fd_ = -1;
 }


/**
 * @brief Write a log entry.
 * 
 * @param a_fp     FILE where to write to.
 * @param a_format fprintf like format.
 * @param ...      Variable arguments.
 */
void casper::inotify::API::Log (FILE* a_fp, const API::What a_what, const char* const a_format, ...)
{
  std::va_list args;
  try {
    const char* what;
    const char* color = LOGGER_RESET_ATTRS;
    switch(a_what) {
    case API::What::Info:
      what = "Info";
      break;
    case API::What::Warning:
      what = "Warning";
      color = LOGGER_COLOR(YELLOW);
      break;      
     case API::What::Error:
      what = "Error";
      color = LOGGER_COLOR(RED);
      break;
    case API::What::Event:
      what = "Event";
      break;
    case API::What::Debug:
      what = "Debug";
      color = LOGGER_COLOR(DARK_GRAY);
      break;
    default:
      what = "???";
      color = LOGGER_COLOR(RED);
      break;
    }
    fprintf(a_fp, "%s, %8d, %-10.10s, ", NowISO8601WithTZ(), pid_, what);
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
      va_end(args);
      fprintf(a_fp, "%s%s" LOGGER_RESET_ATTRS, color, length > 0 ? std::string { temp.data(), length }.c_str() : "");
    }
    fprintf(a_fp, "\n");
    fflush(a_fp);
  } catch (std::exception& a_exception) {
    va_end(args);
    throw a_exception;
  }
}

/**
 * @return ISO8601WithTZ.
 */
const char* const casper::inotify::API::NowISO8601WithTZ ()
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

  const int w = snprintf(log_time_buffer_, 26, "%04u-%02u-%02uT%02u:%02u:%02u+%02u:%02u",
			 year,month, day, hours, minutes, seconds,
			 0, 0
  );

  if ( w <=0 || w > 25 ) {
    throw inotify::Exception("Unable to convert epoch to ISO8601WithTZ!");
  }

  return log_time_buffer_;
}

// MARK: -

void casper::inotify::API::DumpFields (FILE* a_fp) const
{
  for ( const auto& it : API::sk_field_id_to_name_map_ ) {
    fprintf(a_fp, "0x%08X - %-16.16s - %12.12s - %s\n", it.first, it.second.name_, it.second.key_, it.second.description_);
  }
  fflush(stdout);
}

// MARK: -

void casper::inotify::API::Spawn (const API::Entry& a_entry,
				  const API::E& a_event)
{
  if ( a_entry.msg_.length() > 0 ) {
    syslog(LOG_DEBUG, "⌁ (%s) MSG %s", a_entry.user_.c_str(), a_entry.msg_.c_str()); 
  }
  syslog(LOG_DEBUG , "⌁ (%s) CMD %s", a_entry.user_.c_str(), a_entry.cmd_.c_str());
  // ...
  std::string cmd, msg;
  const std::map<const std::string*, std::string*> strings = { { &a_entry.cmd_, &cmd}, { &a_entry.msg_, &msg} };
  for ( auto it : strings ) {
    (*it.second) = Replace((*it.first) , "§.event"   , a_event.name_);
    (*it.second) = Replace((*it.second), "§.object"  , a_event.object_type_c_str_);
    (*it.second) = Replace((*it.second), "§.name"    , a_event.object_name_c_str_);
    (*it.second) = Replace((*it.second), "§.datetime", a_event.iso_8601_with_tz_);
    (*it.second) = Replace((*it.second), "§.hostname", hostname_);
  }

  // TODO: or
  
  std::map<const char* const, std::string> vars = {
     { "CASPER_INOTIFY_EVENT"   , a_event.name_              },
     { "CASPER_INOTIFY_OBJECT"  , a_event.object_type_c_str_ },
     { "CASPER_INOTIFY_NAME"    , a_event.object_name_c_str_ },
     { "CASPER_INOTIFY_DATETIME", a_event.iso_8601_with_tz_  },
     { "CASPER_INOTIFY_HOSTNAME", hostname_                  },
     { "CASPER_INOTIFY_MSG"     , msg                        }
  };

  // ...
  for ( auto it : strings ) {
    for ( auto it2 : vars ) {
      (*it.second) = Replace((*it.first) , ( "${" + std::string(it2.first) + "}" ) , it2.second);
    }
  }

  // ...
  const pid_t pid = fork();
  if ( 0 > pid )  { // ... unable to fork ...
    // ... log ...
    syslog(LOG_ERR, "unable to launch '%s' - fork failure", cmd.c_str());
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
    // ... syslog ...
    openlog(abbr_.c_str(), (LOG_CONS | LOG_PID), LOG_CRON);
    syslog(LOG_NOTICE, "(%s) CMD %s", a_entry.user_.c_str(), cmd.c_str());
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
    //
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
	  0 != setenv("SHELL"             , pwd->pw_shell    , 1) ||
	  0 != setenv("CASPER_INOTIFY_MSG", msg.c_str()      , 1)
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
      syslog(LOG_ERR, "unable to launch %s", cmd.c_str());
      syslog(LOG_ERR, "uanble to %s - ( %d ) %s", error.what_, error.no_, error.str_.c_str());
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
  syslog(LOG_NOTICE , "⇥  (%s) CMD %s", a_entry.user_.c_str(), cmd.c_str());
}

const std::string casper::inotify::API::Replace (std::string a_value, const std::string& a_from, const std::string& a_to)
{
  size_t start_pos = 0;
  while ( std::string::npos != ( start_pos = a_value.find(a_from, start_pos) ) ) {
    a_value.replace(start_pos, a_from.length(), a_to);
    start_pos += a_to.length();
  }
  return a_value;
}
