/**
 * @file api.h
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
#ifndef CASPER_INOTIFY_API_H_
#define CASPER_INOTIFY_API_H_

#include <string>
#include <vector>
#include <map>
#include <set>

#include <exception>
#include <cstdio>     // std::vsnprintf
#include <cstdarg>    // va_start, va_end, std::va_list

#include "json/json.h"

#include <functional>

namespace casper
{
  
  namespace inotify
  {        

    class Exception final
    {
      
    private: // Data
      
      std::string what_;
      
    public: // Constructor(s) / Destructor
      
	Exception (const char* const a_format, ...) __attribute__((format(printf, 2, 3)))
      {
        auto temp   = std::vector<char> {};
        auto length = std::size_t { 512 };
        std::va_list args;
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
        what_ = length > 0 ? std::string { temp.data(), length } : "";
      }
      
      virtual ~Exception ()
      {
        /* empty */
        
      }
      
    public: // overrides
	
      /**
       * @return An explanatory string.
       */
      virtual const char* what() const throw()
      {
        return what_.c_str();
      }
      
    };
    
    class API final
    {
      
    private: // Enum(s)
      
	  typedef enum {
	    File,
	    Directory
	  } Kind;
      
	  typedef enum {
	    Info,
	    Warning,
	    Error,
	    Event,
	    Debug
	  } What;
      
    private: // Data Type(s)

	  typedef struct _E {
	    uint32_t    mask_;
	    char        object_type_c_;
	    const char* object_type_c_str_;
	    const char* object_name_c_str_;
	    char        parent_object_type_c_;
	    const char* parent_object_name_;
	    bool        inside_a_watched_directory_;
	    std::string name_;
	    std::string iso_8601_with_tz_;
	  } E;

	  typedef struct _Entry {
	    const Kind        kind_;    //!< One of \link Kind \link.
	    const std::string uri_;     //!<
	    uint32_t          mask_;    //!<
	    int               wd_;      //!< Watch descriptor.
	    const std::string user_;    //!<
	    const std::string cmd_;     //!< Command to execute.
	    const std::string msg_;     //!< Message to export CASPER_INOTIFY_MESSAGE.
	    std::string       pattern_; //!<
	    std::string       error_;   //!<
	    std::string       warning_; //!<	    
	    std::function<bool(const struct _Entry&, const E&)> handler_; //!<
	  } Entry;
      
	  typedef struct {
	    std::vector<Entry*>   vector_;
	    std::map<int, Entry*> good_;
	    std::vector<Entry*>   bad_;
	  } Entries;
      
	  typedef struct {
	    std::set<std::string> directories_;
	    std::set<std::string> files_;
	  } WatchedSets;
      
	  typedef struct {
	    std::string user_;
	    std::string message_;
	    std::string command_;
	  } Defaults;

	private: // Static Const Data
      
	  typedef struct {
	    const char* const name_;
	    const char* const key_;
	    const char* const description_;
	  } FieldInfo;
      
	  static const std::map<uint32_t, const FieldInfo> sk_field_id_to_name_map_;
	  static const std::map<std::string, uint32_t>     sk_field_key_to_id_map_;
	  
	private: // Const Data
      
	  const pid_t       pid_;
	  const std::string abbr_;
	  const std::string info_;
	  
    private: // Data
      
	  FILE*       log_out_fd_;
	  
	  int         inotify_fd_;
      
	  Defaults    defaults_;
	  Entries     entries_;
	  
	  WatchedSets sets_;
	  
	  char        log_time_buffer_[27];
	  int         log_entry_ml_;
	  
	  char        hostname_[1024];

    public: // Constructor(s) / Destructor
      
      API (const API&) = delete;
      API (const API&&) = delete;
      API () = delete;
      API(const char* const a_name, const char* const a_version);
      virtual ~API();
      
    public: // Method(s) // Function(s)
      
      int  Load   (const std::string& a_uri);
      int  Watch  ();
      void Unload ();
      
    private: // Method(s) // Function(s)
      
	  bool Register   (Entry* a_entry);
	  bool Unregister (Entry* a_entry);
	  void Wait ();
      
	  void Log      (FILE* a_fp, const What a_what, const char* const a_format, ...) __attribute__((format(printf, 4, 5)));
	  void LogAction (const char* const a_action,
                      const Entry& a_entry);
	  void LogEvent (const int a_level, const Entry& a_entry, const E& a_event,
                     const std::vector<std::string>& a_actions);
      
	  const char* const NowISO8601WithTZ ();
      
	  void DumpFields (FILE* a_fp) const;
      
	  bool               SpecialHandler (const Entry& a_entry, const E& a_event);
	  void               Spawn (const Entry& a_entry,
                                const E& a_event);
	  const std::string  Replace (std::string a_value, const std::string& a_from, const std::string& a_to);
      
	private: // Method(s) / Function(s)
      
	  inline Entry* NewEntry (const API::Kind a_kind,
                              const std::string& a_uri, uint32_t a_mask,
                              const Json::Value& a_object,
                              std::function<bool(const struct _Entry&, const E&)> a_handler = nullptr) const
	  {
	    static const Json::Value dummy_string = Json::Value("");
	    return new API::Entry{
          /* kind_    */ a_kind,
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
	    };
	  }

    }; // end of class 'API'
    
  } // end of namespace 'inotify'
  
} // end of namespace 'casper'
        
#endif // CASPER_INOTIFY_API_H_
