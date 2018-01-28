import java.net.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 * Class Scanlog
 * 
 * @author Marco Ubertone La Rocca
 * @version 1.1
 */
public class Scanlog extends JPanel implements ActionListener {
	private static final long serialVersionUID = 1L;
	private static final String newline = "\n";

	private JButton openButton, execButton, saveButton;
	private JTextArea log;
	private JFileChooser fc;
	private boolean analyzed = false;

	/** Filtro per file di log */
	private FileFilter logFilter = null;
	/** Filtro per file di testo */
	private FileFilter txtFilter = null;

	/** File di log selezionato */
	private File select;
	/** File di report salvato */
	private File save;
	/** Lista dei client */
	private List<Client> listClient;

	/**
	 * Costruttore
	 */
	public Scanlog() {
		super(new BorderLayout());

		log = new JTextArea(5, 20);
		log.setMargin(new Insets(5, 5, 5, 5));
		log.setEditable(false);

		JScrollPane logScrollPane = new JScrollPane(log);

		fc = new JFileChooser();

		URL imgOpen = Scanlog.class.getResource("images/Open.gif");
		openButton = new JButton("Seleziona File", new ImageIcon(imgOpen));
		openButton.addActionListener(this);

		URL imgExec = Scanlog.class.getResource("images/Exec.gif");
		execButton = new JButton("Esegui", new ImageIcon(imgExec));
		execButton.addActionListener(this);

		URL imgSave = Scanlog.class.getResource("images/Save.gif");
		saveButton = new JButton("Salva Report", new ImageIcon(imgSave));
		saveButton.addActionListener(this);

		JPanel buttonPanel = new JPanel();
		buttonPanel.add(openButton);
		buttonPanel.add(execButton);
		buttonPanel.add(saveButton);
		add(buttonPanel, BorderLayout.PAGE_START);
		add(logScrollPane, BorderLayout.CENTER);
	}

	/**
	 * Controllo esistenza client nella lista
	 * 
	 * @param client
	 *            Stringa contenente l'IP del client
	 * @return Client (se la ricerca ha esito positivo) altrimenti null
	 */
	private Client searchClient(String client) {
		for (int c = 0; c < listClient.size(); c++) {
			if (listClient.get(c).getClient().compareTo(client) == 0)
				return listClient.get(c);
		}
		return null;
	}

	/**
	 * Conversione dei millisecondi in hh:mm:ss [ms]
	 * 
	 * @param timeNavigation
	 *            Intero contenente i millisecondi della navigazione
	 * @return Tempo della navigazione in formato Stringa
	 */
	private String convertTime(int timeNavigation) {
		int time = timeNavigation / 1000;
		String seconds = Integer.toString(time % 60);
		String minutes = Integer.toString((time % 3600) / 60);
		String hours = Integer.toString(time / 3600);

		if (seconds.length() < 2)
			seconds = "0" + seconds;
		if (minutes.length() < 2)
			minutes = "0" + minutes;
		if (hours.length() < 2)
			hours = "0" + hours;

		return hours + ":" + minutes + ":" + seconds + " [" + timeNavigation
				% 1000 + "ms]";
	}

	/**
	 * Funzione per il salvataggio del report generato sul file di log
	 * analizzato
	 * 
	 * @throws IOException
	 */
	private void rescue() throws IOException {
		int timeNavigation;
		FileWriter fw = new FileWriter(save);

		BufferedWriter bw = new BufferedWriter(fw);
		bw.write("________REPORT NAVIGAZIONE HTTP________");
		bw.newLine();
		bw.newLine();
		bw.newLine();

		for (int client = 0; client < listClient.size(); client++) {
			bw.newLine();
			bw.write("Client: " + listClient.get(client).getClient());
			bw.newLine();
			bw.write("Siti visitati:");
			bw.newLine();
			for (int s = 0; s < listClient.get(client).getListServer().size(); s++) {
				bw.write("\t");
				bw.write(listClient.get(client).getListServer().get(s)
						.getServer());
				bw.newLine();
			}
			timeNavigation = listClient.get(client).getTime().getTotalTime();
			bw.write("Tempo di naviagzione: " + convertTime(timeNavigation));
			bw.newLine();
			bw.write("Bytes di naviagzione: "
					+ listClient.get(client).getBytes().getTotalBytes());
			bw.newLine();
			bw.write("_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _");
			bw.newLine();
			bw.newLine();
		}
		bw.flush();
		bw.close();
		fw.close();
	}

	/**
	 * Funzione per l'analisi del file di log
	 * 
	 * @throws IOException
	 */
	private void analyzing() throws IOException {
		Client c;
		listClient = new ArrayList<Client>();

		// Lettura File Di Log
		FileInputStream fis = new FileInputStream(select);
		InputStreamReader isr = new InputStreamReader(fis);
		BufferedReader br = new BufferedReader(isr);
		String line = null;
		line = br.readLine();

		while (line != null) {
			if (line.length() != 0 && line.charAt(0) != '#') {
				LineLOG __LINELOG__ = new LineLOG(line);

				// Controllo presenza Client nella lista
				String __CLIENT__ = __LINELOG__.lineClient();
				if ((c = searchClient(__CLIENT__)) == null) {
					c = new Client(__CLIENT__);
					listClient.add(c);
				}
				// Controllo presenza Server nella lista
				String __SERVER__ = __LINELOG__.lineServer();
				if (c.searchServer(__SERVER__) == null)
					c.addServer(__SERVER__);

				// Incremento byte di navigazione
				int __BYTES__ = __LINELOG__.lineBytes();
				c.getBytes().incrementBytes(__BYTES__);

				// Aggiornamento tempo di navigazione
				int BeginTime = c.getTime().getBeginTime();
				int __BEGINTIME__ = __LINELOG__.lineBeginTime();
				if (BeginTime == 0
						|| (BeginTime > __BEGINTIME__ && __BEGINTIME__ != 0))
					c.getTime().updateBeginTime(__BEGINTIME__);

				int EndTime = c.getTime().getEndTime();
				int __ENDTIME__ = __LINELOG__.lineEndTime();
				if (EndTime == 0 || EndTime < __ENDTIME__)
					c.getTime().updateEndTime(__ENDTIME__);
			}
			line = br.readLine();
		}

		br.close();
		isr.close();
		fis.close();
	}

	/**
	 * Funzione per la gestione delle funzionalità dei pulsanti
	 */
	public void actionPerformed(ActionEvent e) {
		fc.setAcceptAllFileFilterUsed(false);

		if (e.getSource() == openButton) { // Selezione file di log
			analyzed = false;

			fc.resetChoosableFileFilters();
			logFilter = new FileNameExtensionFilter("File LOG", "log");
			fc.addChoosableFileFilter(logFilter);

			int returnVal = fc.showOpenDialog(Scanlog.this);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				select = fc.getSelectedFile();
				log.append("File selezionato: " + select.getName() + newline);
			} else
				log.append("Selezione annullata dall'utente" + newline);
		} else if (select == null) // Nessun file di log selezionato
			log.append("Selezionare file da analizzare" + newline);
		else if (e.getSource() == execButton) { // Selezione esegui
			log.append("Inizio analisi..." + newline);
			try {
				analyzing();
			} catch (Exception e1) {
				log.append("Errore analisi: " + e1.toString() + newline);
				e1.printStackTrace();
			}
			analyzed = true;
			log.append("Analisi completata" + newline);
		} else if (e.getSource() == saveButton) { // Selezione salva
			if (!analyzed)
				log.append("Nessun report da salvare" + newline);
			else {
				fc.resetChoosableFileFilters();
				txtFilter = new FileNameExtensionFilter("File TXT", "txt");
				fc.addChoosableFileFilter(txtFilter);

				int returnVal = fc.showSaveDialog(Scanlog.this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					save = fc.getSelectedFile();
					save = new File(save.getAbsolutePath() + ".txt");
					log.append("Salvataggio report..." + newline);
					try {
						rescue();
					} catch (IOException e1) {
						log.append("Errore salvataggio: " + e1.toString()
								+ newline);
						e1.printStackTrace();
					}
					log.append("Report " + save.getName() + " salvato"
							+ newline);
				} else
					log.append("Salvataggio annullato dall'utente" + newline);
			}
		}
	}

	/**
	 * Funzione per la creazione dell'interfaccia grafica
	 */
	private static void createAndShowGUI() {
		try {
			UIManager.setLookAndFeel(UIManager
					.getCrossPlatformLookAndFeelClassName());
		} catch (Exception e) {
		}
		JFrame.setDefaultLookAndFeelDecorated(true);

		JFrame frame = new JFrame("Scanlog");
		URL imgIcon = Scanlog.class.getResource("images/Scan.gif");
		frame.setIconImage(new ImageIcon(imgIcon).getImage());
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.add(new Scanlog());
		frame.pack();
		frame.setVisible(true);
	}

	/**
	 * Main
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		javax.swing.SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				createAndShowGUI();
			}
		});
	}
}
