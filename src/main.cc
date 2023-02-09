/**
 * @file main.cc
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
#include "version.h"

int main( int argc, char **argv ) {
  casper::inotify::API api;

  int rv;
  try {
    if ( 0 == ( rv = api.Load("/etc/" CASPER_INOTIFY_NAME "/conf.json") ) ) {
      rv = api.Watch();
      api.Unload();
    }
  } catch (const casper::inotify::Exception& a_n_e) {
    rv = -1;
    fprintf(stderr, "%s\n", a_n_e.what());
    api.Unload();
  } catch (const std::exception& a_e) {
    rv = -1;
    fprintf(stderr, "%s\n", a_e.what());
    api.Unload();
  }
  return rv;
}
