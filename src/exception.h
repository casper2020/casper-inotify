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
#ifndef CASPER_INOTIFY_EXCEPTION_H_
#define CASPER_INOTIFY_EXCEPTION_H_

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
            
            Exception() = delete;
            
            /**
             * @brief Default construtor.
             *
             * @param a_format printf like format followed by a variable number of arguments
             * @param ...
             */
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
            
            /**
             * @brief Destructor.
             */
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
            
        }; // end of class 'Exception'
        
    } // end of namespace 'inotify'
    
} // end of namespace 'casper'

#endif // CASPER_INOTIFY_EXCEPTION_H_
