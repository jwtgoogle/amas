- strs.txt

    保存的是常见的APK的字符串，通过instrs取完全不一样的APK的交集而成。

- action.txt permissions.txt

    保存的是初始化训练数据的关键字

    其中permissions.txt，来自AndroidManifest.xml

- AndroidManifest.xml

  来自源码 //device/apps/common/AndroidManifest.xml

- words.txt

  保存的是单词

- labels

  是生成的样本类名(恶意软件分类)

- data.pkl

  保存的训练模型

- api-versions.xml

  来自 android sdk 的api，用于过滤公共 api
