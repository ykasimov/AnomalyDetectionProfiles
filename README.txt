There are two notebooks with an implementation of anomaly detection algorithms using profiles.
The notebook One-class_svm.ipynb implements training and testing of our anomaly detection approach using One-Class SVM algorithm
The notebook LOF_model.ipynb implements training and testing of our anomaly detection approach using Local Outlier Factor algorithm

We provide already trained models for One-Class SVM and a file with parameters for LOF algorithm.
We provide profiles for training for the following datasets:

1) Capture-mixed-7.profiles.json and Capture-mixed-8.profiles.json are generated using the first dataset and Emotet malware (for more information about the datasets please see the pdf with thesis)

2) ---capture-WinFull-1.profiles.json are profiles generated from the normal capture of the second dataset. 
   ---CTU-Mixed-2018-04-04_mixed.profiles.json are profiles generated from the capture after the infection. Malware was DarkVNC.
   ---CTU-Mixed-7.profiles.json are profiles generated from the second capture after the infection. Malware was Simba. 

We provide requirements.txt file with all libraries to run the notebooks. 


To generate profiles from flows use ./source/parse-binet/dataGather.py

How to generate profiles:

1) open ./source/parse-binet/fileToAnalyze.py
2) change the variable BINETFLOW to point to a file with flows
3) change the variable COMPUTERSTOANALYZER to point to a file computers.md
4) Create the file computers.md in path specified in COMPUTERSTOANALYZER should contain the ip adress of the host you want to analyze.
 	You can create the file as follows:   echo '10.0.2.15:aaa' > /path/to/computers.md
	Then the variable COMPUTERSTOANALYZER='/path/to/computers.md'
For more information about profile generation see: https://github.com/Kobtul/parse-binet/tree/thesis
