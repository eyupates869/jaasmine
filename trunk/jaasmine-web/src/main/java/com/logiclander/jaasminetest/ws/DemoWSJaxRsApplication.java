/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package com.logiclander.jaasminetest.ws;

import java.util.HashSet;
import java.util.Set;
import javax.ws.rs.core.Application;

/**
 *
 * @author agherna
 */
public class DemoWSJaxRsApplication extends Application {

    HashSet<Object> singletons = new HashSet<Object>();

    public DemoWSJaxRsApplication() {
        singletons.add(new HelloService());
    }

    public Set<Class<?>> getClasses() {
        Set<Class<?>> s = new HashSet<Class<?>>();
//        s.add(HelloService.class);

        return s;
    }


    public Set<Object> getSingletons() {
        return singletons;
    }
}
