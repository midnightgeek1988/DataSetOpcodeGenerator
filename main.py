# Dataset Generator
from __future__ import division
from DataBaseHandler import DatabaseHandler
from os import walk
from androdd import dump_all_method
from collections import Counter
from datetime import datetime
import os
import re
import urllib
import urllib2
from shutil import copyfile
import unicodedata
import time
import json
import operator
import itertools 

def get_all_files_in_directory(directory):
    return [temp for (dir_path, dir_names, file_names) in walk(directory) for temp in file_names]


def get_all_files_with_path_in_directory(directory):
    return [(directory_path + '/' + item) for (directory_path, directory_names, file_names) in walk(directory) for item
            in file_names if file_names]


def write_arff(dataset, class1, class2, class_top):
    logger("Start write arff")
    final_op_set = []
    opcode_bank = {}
    index_helper_x = 0
    seen = set()
    for item in class1:
        for key, value in item.iteritems():
            splitter = key.strip().split()
            if splitter[0] not in seen:
                final_op_set.append(splitter[0])
                opcode_bank[splitter[0]] = index_helper_x
                index_helper_x = index_helper_x + 1
                seen.add(splitter[0])
            if splitter[1] not in seen:
                final_op_set.append(splitter[1])
                opcode_bank[splitter[1]] = index_helper_x
                index_helper_x = index_helper_x + 1
                seen.add(splitter[1])
    for item in class2:
        for key, value in item.iteritems():
            splitter = key.strip().split()
            if splitter[0] not in seen:
                final_op_set.append(splitter[0])
                opcode_bank[splitter[0]] = index_helper_x
                index_helper_x = index_helper_x + 1
                seen.add(splitter[0])
            if splitter[1] not in seen:
                final_op_set.append(splitter[1])
                opcode_bank[splitter[1]] = index_helper_x
                index_helper_x = index_helper_x + 1
                seen.add(splitter[1])
    data_fp = open(dataset, "w")
    data_fp.write('''@RELATION OpcodeSequence
           ''')
    data_fp.write("\n")
    for opc_i in final_op_set:
        for opc_j in final_op_set:
            name = str(opc_i) + str(opc_j)
            name_ch = str(opc_i) +" "+ str(opc_j)
            if ((len([item_t for item_t in class_top if item_t[0] == name_ch])==1)):
                data_fp.write("@ATTRIBUTE %s NUMERIC \n" % name)
    data_fp.write("@ATTRIBUTE Class1 {mal,bin} \n")
    data_fp.write("\n")
    data_fp.write("@DATA")
    data_fp.write("\n")

    for item in class1:
        for opc_i in final_op_set:
            for opc_j in final_op_set:
                key = str(str(opc_i) + " " + str(opc_j))
                # print key
                if (len([item_t for item_t in class_top if item_t[0] == key])==1):
                    if key in item:
                        data_fp.write(str(item[str(opc_i) + " " + str(opc_j)]) + ",")
                    else:
                        data_fp.write("0" + ",")
        data_fp.write("mal")
        data_fp.write("\n")

    for item in class2:
        for opc_i in final_op_set:
            for opc_j in final_op_set:
                key = str(str(opc_i) + " " + str(opc_j))
                if (len([item_t for item_t in class_top if item_t[0] == key])==1):
                    if key in item:
                        data_fp.write(str(item[str(opc_i) + " " + str(opc_j)]) + ",")
                    else:
                        data_fp.write("0" + ",")
        data_fp.write("bin")
        data_fp.write("\n")
    logger("End write arff")

def weight_function(dataset_sample_opcode_sequence, dataset_sample_opcodes, table_opcode_sequence):
    logger("Start weight function")
    logger("weight, table opcode sequence" + " : " + str(len(table_opcode_sequence)))
    calculated_weight = []
    for sample in range(0, len(dataset_sample_opcode_sequence)):
        logger("weight, sample opcodes" + " : " + str(len(dataset_sample_opcodes[sample])))
        logger("weight, sample opcodes seq : " + str(len(dataset_sample_opcode_sequence[sample])))
        sample_vector = {}
        dict_y = Counter(dataset_sample_opcodes[sample])
        dict_x = Counter(dataset_sample_opcode_sequence[sample])
        for row in table_opcode_sequence:
            # print str(op_seq)
            operators = row.strip().split()
            sample_vector[row] = round(dict_x[row] / dict_y[operators[0]], 3) if (
                    (operators[0] in dict_y) and (dict_y[operators[0]] != 0) and (row in dict_x)) else 0
        calculated_weight.append(sample_vector)
        logger("calculated weight len : " + str(len(sample_vector)))
    logger("End weight function")
    return calculated_weight


def fill_samples_table(repo):
    db = DatabaseHandler()
    db.recreats_table_samples()
    files = get_all_files_in_directory(repo)
    for items in files:
        try:
            if str(items).endswith('.apk'):
                db.insert_a_sample(items, '')
        except Exception as e:
            print e


def update_samples_label(repo):
    db = DatabaseHandler()
    samples = db.select_sample_all()
    for item in samples:
        isSend = False
        while not isSend:
            lable = make_virus_total_request(item[1].split('.')[0])
            if 'Forbidden' != lable:
                shash = unicodedata.normalize('NFKD', item[1]).encode('ascii', 'ignore')
                rowcount = db.update_sample_lable(shash, lable)
                print item[0], ' -> ', item[1], " : ", lable, ' RowCount : ', str(rowcount)
                if (int(lable) == 0):
                    copyfile(repo + item[1], repo + "0/" + item[1])
                elif (int(lable) == 1):
                    copyfile(repo + item[1], repo + "1/" + item[1])
                elif int(lable) > 1 and int(lable) <= 5:
                    copyfile(repo + item[1], repo + "5/" + item[1])
                elif int(lable) > 5 and int(lable) <= 10:
                    copyfile(repo + item[1], repo + "10/" + item[1])
                else:
                    copyfile(repo + item[1], repo + "more/" + item[1])
                isSend = True
            else:
                print item[0], ' -> ', item[1], ' : Forbidden'
                time.sleep(120)


def make_virus_total_request(hash, db=None):
    try:
        params = {'apikey': 'YOUR_KEY', 'resource': hash}
        data = urllib.urlencode(params)
        result = urllib2.urlopen('https://www.virustotal.com/vtapi/v2/file/report', data)
        jdata = json.loads(result.read())
        return parse(jdata, hash)
    except Exception as e:
        print e
        return 'Forbidden'

def parse(it, md5, verbose=True, jsondump=True):
    if it['response_code'] == 0:
        print md5 + " -- Not Found in VT"
        return 0
    else:
        return it['positives']

def extract_opcode(path_to_dir):
    logger("Start extract opcode")
    full_address = path_to_dir.strip('\n')
    list_files = get_all_files_with_path_in_directory(full_address)
    list_opcode = []
    for index in range(0, len(list_files)):
        temp_file = list_files[index]
        try:
            if temp_file.endswith('.ag'):
                file_open = open(temp_file)
                # print temp_file
                for m in file_open:
                    b = m.strip()
                    word = m.strip().split() if re.match('^\\d', b) else ''
                    if len(word) >= 2:
                        list_opcode.append(word[2])
        except Exception as e:
            print e
    logger("opcode counter : " + str(len(list_opcode)))
    logger("Unique opcode counter : " + str(len(Counter(list_opcode))))
    logger("End extract opcode")
    return list_opcode


def construct_opcode_sequence(path_to_dir, list_general, n):
    logger("Start construct opcode sequence")
    list_opcode_sequence = [list_general[item] + ' ' + list_general[item + 1] for item in
                            range(0, len(list_general) - n + 1)]
    logger("opcode sequence counter " + str(len(list_opcode_sequence)))
    logger("End construct opcode sequence")
    return list_opcode_sequence


def opcode_sequence_generator(repo, dump_method_dir):
    db = DatabaseHandler()
    samples = db.select_sample_all()
    unique_opcode_sequence = []
    sample_mal_opcode_sequence = []
    sample_bin_opcode_sequence = []
    sample_mal_opcode = []
    sample_bin_opcode = []
    sample_bin_name = []
    sample_mal_name = []
    seen = set()
    logger("Start Process : "+str(len(samples)))
    indexer = 1
    for sample_item in samples:
        try:
            logger("++++++ Progress : "+sample_item[1]+" -> "+str(indexer)+"/"+str(len(samples)))
            indexer=indexer+1
            # Generate Opcode Seq for every sample
            logger("Start Sample : " + sample_item[1])
            if sample_item[1].endswith(".apk"):
                logger("Start dumping")
                dump_all_method(repo + sample_item[1], dump_method_dir)
                logger("End dumping")
                opcode_list = extract_opcode(dump_method_dir)
                opcode_sequence = construct_opcode_sequence(dump_method_dir, opcode_list, 2)
                # Add opcode seq to class belong
                if sample_item[1].startswith('bin_') and sample_item[1].endswith(".apk"):
                    sample_bin_opcode_sequence.append(opcode_sequence)
                    sample_bin_opcode.append(opcode_list)
                    sample_bin_name.append(sample_item[1])
                elif sample_item[1].endswith(".apk"):
                    sample_mal_opcode_sequence.append(opcode_sequence)
                    sample_mal_opcode.append(opcode_list)
                    sample_mal_name.append(sample_item[1])
                # Generate a Sequence banck
                for opcode_item in opcode_sequence:
                    if opcode_item not in seen:
                        unique_opcode_sequence.append(opcode_item)
                        seen.add(opcode_item)
            logger("End Sample")
        except Exception as e:
            print e
    mal_class = weight_function(sample_mal_opcode_sequence, sample_mal_opcode, unique_opcode_sequence)
    bin_class = weight_function(sample_bin_opcode_sequence, sample_bin_opcode, unique_opcode_sequence)
    for top_count in range(1,100):
        mal_class_sum = featureSelection(mal_class,unique_opcode_sequence,top_count*10)
        bin_class_sum = featureSelection(bin_class,unique_opcode_sequence,top_count*10)
        write_arff(repo + 'result'+str(top_count*10)+'.arff', mal_class, bin_class,mal_class_sum+bin_class_sum)


def featureSelection(dataSet,uniq_opcode_seq,top_count):
    sum = 0.0
    result= {}
    for opc in uniq_opcode_seq:
        for dataSet_sample in dataSet:
            if (opc in dataSet_sample):
                sum =  sum + dataSet_sample[opc] 
        result[opc] = sum
        sum=0.0
    sorted_x = sorted(result.items(), key=operator.itemgetter(1),reverse=True)    
    return sorted_x[:top_count]
    #return {k: v for k, v in sorted(result.items(), key=lambda item: item[1])}

def logger(tag):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S:%fZ")
    print '(' + current_time + ') : ' + tag


def menu_select():
    db = DatabaseHandler()
    repo = raw_input("Directory Address : ")
    if not repo.endswith('/'):
        repo = repo + '/'
    try:
        os.mkdir(repo + 'dec_bank')
    except OSError:
        pass
    dump_method_dir = repo + 'dec_bank'
    while True:
        print '********* DataSet Generator *********'
        print 'Enter 1 For Fill Samples Table'
        print 'Enter 2 For Label Sample With VT Api'
        print 'Enter 3 For Upcode sequence Generator'
        print 'Enter 4 For Clear Samples Table'
        print 'Enter 5 For Exit'
        menu = raw_input("Enter Number : ")
        if menu == '1':
            fill_samples_table(repo)
        elif menu == '2':
            update_samples_label(repo)
        elif menu == '3':
            opcode_sequence_generator(repo, dump_method_dir)
        elif menu == '4':
            db.clear_table_Dataset()
        elif menu == '5':
            break
        else:
            print 'Wrong Number'


if __name__ == '__main__':
    menu_select()
