package org.lili.security;

import org.junit.Test;


public class Base64Test {

    @Test
    public void encode() {
        String data = " where gid in (select users_id from Teams_Users where teams_id='bfdb228e-dde7-7a3d-e6c1-06e8e24e5f2e')";
        byte[] result = Base64.encode(data.getBytes());
        System.out.println(data);
        System.out.println(new String(result));
        System.out.println(new String(Base64.decode(new String(result))));
    }
}