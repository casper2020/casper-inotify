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

	  typedef struct {
	    bool              f_only_; //!<
	    const Kind        kind_;   //!< One of \link Kind \link.
	    const std::string uri_;    //!<
	    uint32_t          mask_;   //!<
	    int               wd_;     //!< Watch descriptor.
	    const std::string cmd_;    //!<
	    std::string       err_;    //!<
	  } Entry;
	  
	  typedef struct {
	    std::vector<Entry*>   vector_;
	    std::map<int, Entry*> map_;
	  } Entries;

	  typedef struct {
	    std::set<std::string> directories_;
	    std::set<std::string> files_;
	  } WatchedSets;

	  typedef struct {
	    char        object_type_c_;
	    const char* object_type_c_str_;
	    const char* object_name_c_str_;
	    char        parent_object_type_c_;
	    const char* parent_object_name_;
	    bool        inside_a_watched_directory_;
	  } E;
	   
	private: // Const Data

	  const pid_t pid_;
	  
        private: // Data

            FILE*       log_out_fd_;

            int         inotify_fd_;
            Entries     entries_;
	    WatchedSets sets_;
	    char        log_time_buffer_[27];

	  std::vector<Entry*> tmp_was_deleted_;
            
        public: // Constructor(s) / Destructor
            
            API (const API&) = delete;
            API (const API&&) = delete;
            API ();
            virtual ~API();
            
        public: // Method(s) // Function(s)
            
            int  Load   (const std::string& a_uri);
            int  Watch  ();
            void Unload ();

        private: // Method(s) // Function(s)

	  void Wait ();

	  void Log (FILE* a_fp, const What a_what, const char* const a_format, ...) __attribute__((format(printf, 4, 5)));
	  const char* const NowISO8601WithTZ ();

        }; // end of class 'API'
        
    } // end of namespace 'inotify'

} // end of namespace 'casper'

        
#endif // CASPER_INOTIFY_API_H_
