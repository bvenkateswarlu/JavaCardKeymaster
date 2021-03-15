package com.android.javacard.test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.android.javacard.keymaster.KMJCardSimApplet;
import com.android.javacard.keymaster.KMRepository;
import com.android.javacard.keymaster.KMType;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;

public class KMRepositorySwitch extends KMType {
  private KMRepository testRepository;
  private CardSimulator simulator;
  AID appletAID;

  public KMRepositorySwitch() {
    testRepository = new KMTestRepository(false);
    simulator = new CardSimulator();
    appletAID = AIDUtil.create("A000000062");
  }

  public void testExecutionContext() {
    KMType.repository = testRepository;
    KMType.heap = testRepository.getHeap();
  }

  public void appletExecutionContext() {
    KMType.repository = KMRepository.instance();
    KMType.heap = KMRepository.instance().getHeap();
  }

  public ResponseAPDU transmit(CommandAPDU apdu) {
    ResponseAPDU response = null;
    // Change the repository context to applet.
    appletExecutionContext();
    try {
      response = simulator.transmitCommand(apdu);
    } finally {
      // Change the repository context back to test.
      testExecutionContext();
    }
    return response;
  }

  public void installAndSelectApplet() {
    // install applet
    simulator.installApplet(appletAID, KMJCardSimApplet.class);
    // Select applet
    simulator.selectApplet(appletAID);
    // Change the repository context back to test.
    testExecutionContext();
  }

  public void deleteApplet() {
    // delete applet.
    simulator.deleteApplet(appletAID);
  }

  public void cleanRepository() {
    testRepository.clean();
  }
}
