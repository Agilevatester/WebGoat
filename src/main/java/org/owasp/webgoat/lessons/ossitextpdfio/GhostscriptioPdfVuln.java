package org.owasp.webgoat.lessons.ossitextpdfio;

import com.itextpdf.io.util.GhostscriptHelper;
import java.io.IOException;

public class GhostscriptioPdfVuln {

  String runGhostScriptImageGeneration(String pdf, String outDir, String image) {

    GhostscriptHelper gs = new GhostscriptHelper();
    try {
      gs.runGhostScriptImageGeneration(pdf, outDir, image);
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (InterruptedException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    return "success";
  }
}
