/*
 * Copyright 2019 Jeremy Jamet / Kunzisoft.
 *     
 * This file is part of KeePass DX.
 *
 *  KeePass DX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  KeePass DX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with KeePass DX.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package com.kunzisoft.keepass.database.load;

import com.kunzisoft.keepass.database.element.PwDatabase;
import com.kunzisoft.keepass.database.exception.InvalidDBException;
import com.kunzisoft.keepass.tasks.ProgressTaskUpdater;

import java.io.IOException;
import java.io.InputStream;

public abstract class Importer<PwDb extends PwDatabase> {

	/**
	 * Load a versioned database file, return contents in a new PwDatabase.
	 *
	 * @param inStream  Existing file to load.
	 * @param password Pass phrase for infile.
	 * @return new PwDatabase container.
	 *
	 * @throws IOException on any file error.
	 * @throws InvalidDBException on database error.
	 */
	public abstract PwDb openDatabase(InputStream inStream, String password, InputStream keyInputStream, ProgressTaskUpdater updater)
		throws IOException, InvalidDBException;

	public PwDb openDatabaseAndBuildIndex(InputStream inStream, String password, InputStream keyInputStream, ProgressTaskUpdater updater)
			throws IOException, InvalidDBException {
		PwDb database = openDatabase(inStream, password, keyInputStream, updater);
		database.populateNodesIndexes();
		return database;
	}

}
