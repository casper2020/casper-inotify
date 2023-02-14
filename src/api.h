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

#include <functional>

#include <sys/inotify.h>
#include <limits.h>

#include "json/json.h"

#include "exception.h"

namespace casper
{
    
    namespace inotify
    {
        
        class API final
        {
            
#define IN_STRUCT_EVENT_SIZE            ( sizeof (struct inotify_event) )
#define IN_MAX_EVENTS_PER_LOOP          1024
#define IN_STRUCT_NAME_FIELD_MAX_LENGTH PATH_MAX
#define IN_BUFFER_MAX_LENGTH            ( IN_MAX_EVENTS_PER_LOOP * ( IN_STRUCT_EVENT_SIZE + IN_STRUCT_NAME_FIELD_MAX_LENGTH )) 

		public: // Enum(s)

    	 typedef enum {
				_Critical = 1,
                _Error    = 2,
                _Warning  = 3,
                _Info     = 4,
                _Event    = 5,
                _Debug    = 6,
            } LogLevel;

        private: // Enum(s)
            
            typedef enum {
                _File      = 0,
                _Directory = 1
            } Type;                   
            
        private: // Data Type(s)
            
            typedef struct _Event {
                uint32_t    mask_;
                char        object_type_c_;
                const char* object_type_c_str_;
                const char* object_name_c_str_;
                char        parent_object_type_c_;
                const char* parent_object_name_;
                bool        inside_a_watched_directory_;
                std::string name_;
                std::string iso_8601_with_tz_;
            } Event;
            
            typedef struct _Entry {
                const Type        type_;    //!< One of \link Type \link.
                const std::string uri_;     //!<
                uint32_t          mask_;    //!<
                int               wd_;      //!< Watch descriptor.
                const std::string user_;    //!<
                const std::string cmd_;     //!< Command to execute.
                const std::string msg_;     //!< Message to export CASPER_INOTIFY_MESSAGE.
                std::string       pattern_; //!<
                std::string       error_;   //!<
                std::string       warning_; //!<
                std::function<bool(const struct _Entry&, const Event&)> handler_; //!<
            } Entry;
            
			typedef struct {
                std::set<std::string> directories_;
                std::set<std::string> files_;
            } WatchedSets;

            typedef struct {
                std::vector<Entry*>   all_;
                std::map<int, Entry*> good_;
                std::vector<Entry*>   bad_;
				WatchedSets 		  uris_;
            } Entries;
                        
            typedef struct {
                std::string user_;
                std::string message_;
                std::string command_;
            } Defaults;

			struct _Log {
            	FILE*       fp_;
				LogLevel    level_;
            	int         entry_ml_;
            	char        time_[27];
			};

			struct _INotify {
				int  fd_;
            	char buffer_[IN_BUFFER_MAX_LENGTH];
			};
            
        private: // Static Const Data
            
            typedef struct {
                const char* const name_;
                const char* const key_;
                const char* const description_;
            } FieldInfo;
            
            static const std::map<uint32_t, const FieldInfo> sk_field_id_to_name_map_;
            static const std::map<std::string, uint32_t>     sk_field_key_to_id_map_;
            
        private: // Const Data
            
            const std::string abbr_;
            const std::string info_;
            
        private: // Data
            
            pid_t       	pid_;
			struct _INotify inotify_;
			struct _Log		log_;
            char        	hostname_[1024];
            Defaults    	defaults_;
            Entries     	entries_;

        public: // Constructor(s) / Destructor
            
            API () = delete;
            API (const API&) = delete;
            API (const API&&) = delete;
            API(const char* const a_name, const char* const a_version);
            virtual ~API();
            
        public: // Method(s) // Function(s)
            
			void Init   (const LogLevel a_level, const std::string& a_uri);
            void Load   (const std::string& a_uri);
            int  Watch  ();
            void Unload ();
            
        private: // Method(s) // Function(s)
            
            bool Register   (Entry* a_entry);
            bool Unregister (Entry* a_entry);
            void Wait ();
            
        private: // Method(s) // Function(s)

            void Log (const LogLevel a_level, const char* const a_format, ...) __attribute__((format(printf, 3, 4)));
			void Log (const Entries& a_entries);
            void Log (const char* const a_symbol, const Entry& a_entry);
            void Log (const int a_level, const Event& a_event, const Entry& a_entry,
					  const std::vector<std::string>& a_actions);

		private: // Method(s) // Function(s)

			void Add 	 (const Type a_type, const Json::Value& a_object,
					  	  const std::string& a_uri, uint32_t a_mask,
					  	  std::function<bool(const struct _Entry&, const Event&)> a_handler = nullptr);
			
			void Track   (Entry* a_entry, const bool a_good, const bool a_log = false);
			void Untrack (Entry* a_entry, const char* const a_reason = nullptr, const bool a_log = false);

			void Ignore  (const Entry& a_entry, const Event& a_event);
            void Spawn   (const Entry& a_entry, const Event& a_event);
            bool Handler (const Entry& a_entry, const Event& a_event);

		private: // Method(s) // Function(s)

            const char* const Now     (char* a_buffer) const;
            const std::string Replace (std::string a_value, const std::string& a_from, const std::string& a_to);
            
        }; // end of class 'API'
        
    } // end of namespace 'inotify'
    
} // end of namespace 'casper'

#endif // CASPER_INOTIFY_API_H_
