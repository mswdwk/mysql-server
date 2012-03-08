/*
 *  Copyright (c) 2011, Oracle and/or its affiliates. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

package testsuite.clusterj;

import java.util.ArrayList;
import java.util.List;

import testsuite.clusterj.model.VarbinaryPK;

public class VarbinaryPKTest extends AbstractClusterJTest {

    protected int NUMBER_OF_INSTANCES = 15;
    protected List<VarbinaryPK> instances = new ArrayList<VarbinaryPK>();

    @Override
    public void localSetUp() {
        createSessionFactory();
        session = sessionFactory.getSession();
        tx = session.currentTransaction();
        try {
            tx.begin();
            session.deletePersistentAll(VarbinaryPK.class);
            tx.commit();
        } catch (Throwable t) {
            // ignore errors while deleting
        }
        createInstances();
        addTearDownClasses(VarbinaryPK.class);
    }

    public void test() {
        insert();
        find();
        update();
        delete();
        failOnError();
    }

    /** Insert all instances.
     */
    protected void insert() {
        session.makePersistentAll(instances);
    }

    /** Find all instances.
     */
    protected void find() {
        for (int i = 0; i < NUMBER_OF_INSTANCES; ++i) {
            byte[] key = getPK(i);
            VarbinaryPK result = session.find(VarbinaryPK.class, key);
            verify(result, i, false);
        }
    }

    /** Blind update every fourth instance.
     */
    protected void update() {
        // update the instances
        for (int i = 0; i < NUMBER_OF_INSTANCES; ++i) {
            if (0 == i % 4) {
                VarbinaryPK instance = createInstance(i);
                instance.setName(getValue(NUMBER_OF_INSTANCES - i));
                session.updatePersistent(instance);
                verify(instance, i, true);
            }
        }
        // verify the updated instances
        for (int i = 0; i < NUMBER_OF_INSTANCES; ++i) {
            if (0 == i % 4) {
                byte[] key = getPK(i);
                VarbinaryPK instance = session.find(VarbinaryPK.class, key);
                verify(instance, i, true);
            }
        }
    }

    /** Blind delete every fifth instance.
     */
    protected void delete() {
        // delete the instances
        for (int i = 0; i < NUMBER_OF_INSTANCES; ++i) {
            if (0 == i % 5) {
                VarbinaryPK instance = createInstance(i);
                session.deletePersistent(instance);
            }
        }
        // verify they have been deleted
        for (int i = 0; i < NUMBER_OF_INSTANCES; ++i) {
            if (0 == i % 5) {
                byte[] key = getPK(i);
                VarbinaryPK instance = session.find(VarbinaryPK.class, key);
                errorIfNotEqual("Failed to delete instance: " + i, null, instance);
            }
        }
    }

    /** The strategy for instances is for the "instance number" to create 
     * the keys by creating a byte[] with the encoded number.
     */
    protected void createInstances() {
        for (int i = 0; i < NUMBER_OF_INSTANCES; ++i) {
            VarbinaryPK instance = createInstance(i);
            if (getDebug()) System.out.println(toString(instance));
            instances.add(instance);
        }
    }

    /** Create an instance of VarbinaryPK.
     * @param index the index to use to generate data
     * @return the instance
     */
    protected VarbinaryPK createInstance(int index) {
        VarbinaryPK instance = session.newInstance(VarbinaryPK.class);
        instance.setId(getPK(index));
        instance.setNumber(index);
        instance.setName(getValue(index));
        return instance;
    }

    protected String toString(VarbinaryPK instance) {
        StringBuffer result = new StringBuffer();
        result.append("VarbinaryPK[");
        result.append(toString(instance.getId()));
        result.append("]: ");
        result.append(instance.getNumber());
        result.append(", \"");
        result.append(instance.getName());
        result.append("\".");
        return result.toString();
    }

    protected byte[] getPK(int index) {
        return new byte[] {0, (byte)(index/256), (byte)(index%256)};
    }

    protected String getValue(int index) {
        return "Value " + index;
    }

    protected void verify(VarbinaryPK instance, int index, boolean updated) {
        errorIfNotEqual("id failed", toString(getPK(index)), toString(instance.getId()));
        errorIfNotEqual("number failed", index, instance.getNumber());
        if (updated) {
            errorIfNotEqual("Value failed", getValue(NUMBER_OF_INSTANCES - index), instance.getName());
        } else {
            errorIfNotEqual("Value failed", getValue(index), instance.getName());

        }
    }

    private String toString(byte[] id) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < id.length; ++i) {
            builder.append(String.valueOf(id[i]));
            builder.append('-');
        }
        return builder.toString();
    }

}
