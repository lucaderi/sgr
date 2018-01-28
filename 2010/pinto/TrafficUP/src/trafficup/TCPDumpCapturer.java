/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package trafficup;

import java.io.IOException;
import jpcap.JpcapCaptor;
import jpcap.packet.Packet;

/**
 *
 * @author Ricardo
 */
public class TCPDumpCapturer extends Capturer {

    private String filename;
    
    public TCPDumpCapturer( String filename ){
        this.filename = filename;
    }

    @Override
    public void start()  {
        try {
            JpcapCaptor captor = null;
            Packet p = null;
            //open file so packets can be read
            captor = JpcapCaptor.openFile(filename);
            if (super.isFilterActive())  captor.setFilter(super.getFilter(), true);

            while ( (p = captor.getPacket()) != null && p != Packet.EOF ) {
                //reads one packet
                //Packet p = captor.getPacket();
                
                //stops when reach EOF, or an error
                //if (p == null || p == Packet.EOF) break;

                super.savePacket(p);
            }

            captor.close();

        } catch (IOException ex) {
            javax.swing.JOptionPane.showMessageDialog(null, ex.getMessage(), "Error reading dump file", javax.swing.JOptionPane.ERROR_MESSAGE);
        }
    }

    @Override
    public void stop() {}

    @Override
    public boolean isRunning() {
        return false;
    }

    @Override
    public String getCapturerName() {
        return this.filename;
    }

    @Override
    public void run(){
        start();
    }


}
