/**
 * @file version.h
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
 * along with casper-inotify. If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
#ifndef CASPER_INOTIFY_VERSION_H_
#define CASPER_INOTIFY_VERSION_H_

#ifndef CASPER_INOTIFY_NAME
#define CASPER_INOTIFY_NAME "casper-inotify"
#endif

#ifndef CASPER_INOTIFY_VERSION
#define CASPER_INOTIFY_VERSION "@VERSION@"
#endif

#ifndef CASPER_INOTIFY_INFO
#define CASPER_INOTIFY_INFO CASPER_INOTIFY_NAME " v" CASPER_INOTIFY_VERSION
#endif

#endif // CASPER_INOTIFY_VERSION_H_
